package explorer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type inventoryQuery struct {
	Namespace  string   `json:"namespace"`
	Snapshot   string   `json:"snapshot"`
	Name       string   `json:"name"`
	Sort       string   `json:"sort"`
	Hidden     []string `json:"hidden"`
	Offset     int      `json:"offset"`
	Limit      int      `json:"limit"`
	All        bool     `json:"all"`
	ShowHidden bool     `json:"showHidden"`
	Refresh    bool     `json:"refresh"`
}

type inventorySummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Review   int `json:"review"`
	Pending  int `json:"pending"`
}

type inventoryPage struct {
	Snapshot   string           `json:"snapshot"`
	CapturedAt time.Time        `json:"capturedAt"`
	ExpiresAt  time.Time        `json:"expiresAt"`
	Status     string           `json:"status"`
	Message    string           `json:"message,omitempty"`
	Pods       []PodView        `json:"pods"`
	States     []State          `json:"states"`
	Summary    inventorySummary `json:"summary"`
	Total      int              `json:"total"`
	Hidden     int              `json:"hidden"`
	Offset     int              `json:"offset"`
	NextOffset int              `json:"nextOffset"`
	HasMore    bool             `json:"hasMore"`
}

type inventoryJob struct {
	cancel                         context.CancelFunc
	timer                          *time.Timer
	created, captured, expires     time.Time
	id, namespace, status, message string
	pods                           []PodView
	states                         []State
	mu                             sync.RWMutex
}

type inventoryStore struct {
	client *Client
	jobs   map[string]*inventoryJob
	mu     sync.Mutex
}

func parseInventoryQuery(w http.ResponseWriter, r *http.Request) (inventoryQuery, error) {
	q := inventoryQuery{}
	if r.Method == "POST" {
		media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.Header.Get("Origin") != "http://"+r.Host || r.Header.Get("X-Peeker-Action") != "query-pods" || media != "application/json" {
			return q, errors.New("Pod queries require a same-origin JSON request")
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024))
		d.DisallowUnknownFields()
		if d.Decode(&q) != nil || d.Decode(&struct{}{}) != io.EOF {
			return q, errors.New("Invalid pod query")
		}
	} else {
		v := r.URL.Query()
		q.Namespace, q.Snapshot, q.Name, q.Sort = v.Get("namespace"), v.Get("snapshot"), v.Get("name"), v.Get("sort")
		q.All, q.Refresh = v.Get("all") == "true", v.Get("refresh") == "true"
		for key, dst := range map[string]*int{"offset": &q.Offset, "limit": &q.Limit} {
			if v.Has(key) {
				value, err := strconv.Atoi(v.Get(key))
				if err != nil {
					return q, errors.New("Invalid page bounds")
				}
				*dst = value
			}
		}
	}
	if q.All && q.Namespace != "" {
		return q, errors.New("Choose a namespace or all namespaces")
	}
	if !q.All && q.Namespace == "" {
		q.Namespace = "default"
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	if q.Sort == "" {
		q.Sort = "risk"
	}
	if (q.Namespace != "" && !validName(q.Namespace, true)) || q.Offset < 0 || q.Limit < 1 || q.Limit > 500 || len(q.Name) > 253 || len(q.Snapshot) > 64 || len(q.Hidden) > 4096 {
		return q, errors.New("Invalid namespace, filter or page bounds")
	}
	if q.Sort != "risk" && q.Sort != "review" && q.Sort != "name" {
		return q, errors.New("Invalid ordering")
	}
	for _, key := range q.Hidden {
		if len(key) > 4096 {
			return q, errors.New("Invalid hidden-workload key")
		}
	}
	if (q.Offset > 0 && q.Snapshot == "") || (q.Refresh && q.Snapshot != "") {
		return q, errors.New("Continue pages with a snapshot; refresh starts a new snapshot")
	}
	return q, nil
}

func (store *inventoryStore) job(q inventoryQuery) (*inventoryJob, int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.client.ctx.Err() != nil {
		return nil, 503, errors.New("Cluster session is closed")
	}
	now := time.Now()
	for id, job := range store.jobs {
		if now.After(job.expires) {
			job.cancel()
			delete(store.jobs, id)
		}
	}
	if q.Snapshot != "" {
		job := store.jobs[q.Snapshot]
		if job == nil || job.namespace != q.Namespace {
			return nil, 410, errors.New("Snapshot expired or belongs to another scope; refresh the inventory")
		}
		return job, 200, nil
	}
	if !q.Refresh {
		var latest *inventoryJob
		for _, job := range store.jobs {
			if job.namespace == q.Namespace && now.Sub(job.created) < collectionTTL && (latest == nil || job.created.After(latest.created)) {
				latest = job
			}
		}
		if latest != nil {
			return latest, 200, nil
		}
	}
	if len(store.jobs) >= 4 {
		if !store.evictCompleted() {
			return nil, 429, errors.New("Four inventory assessments are active; retry shortly")
		}
	}
	if q.Refresh {
		store.client.invalidate()
	}
	ctx, cancel := context.WithTimeout(store.client.ctx, 45*time.Second)
	job := &inventoryJob{id: rand.Text(), namespace: q.Namespace, status: "loading", created: now, expires: now.Add(2 * time.Minute), pods: []PodView{}, states: []State{}, cancel: cancel}
	store.jobs[job.id] = job
	go job.load(ctx, store.client)
	id := job.id
	job.timer = time.AfterFunc(2*time.Minute, func() { store.mu.Lock(); defer store.mu.Unlock(); delete(store.jobs, id) })
	return job, 200, nil
}

func (store *inventoryStore) evictCompleted() bool {
	var oldest *inventoryJob
	for _, job := range store.jobs {
		job.mu.RLock()
		finished := job.status == "complete" || job.status == "error"
		job.mu.RUnlock()
		if finished && (oldest == nil || job.created.Before(oldest.created)) {
			oldest = job
		}
	}
	if oldest == nil {
		return false
	}
	oldest.cancel()
	if oldest.timer != nil {
		oldest.timer.Stop()
	}
	delete(store.jobs, oldest.id)
	return true
}

func (job *inventoryJob) load(ctx context.Context, client *Client) {
	defer job.cancel()
	s := client.snapshot(ctx, job.namespace, false)
	if job.prepare(s) {
		job.assess(ctx, s, client.Assessment)
	}
}

func (job *inventoryJob) prepare(s Snapshot) bool {
	job.mu.Lock()
	defer job.mu.Unlock()
	job.states, job.captured = s.states(), time.Now().UTC()
	if !s.available("pods") {
		job.status, job.message = "error", s["pods"].State.Message
		return false
	}
	for _, p := range s.items("pods") {
		v := podView(p, s)
		v.Risk = RiskSummary{Level: "pending", TopFinding: "Assessment pending"}
		job.pods = append(job.pods, v)
	}
	job.status = "assessing"
	return true
}

func (job *inventoryJob) assess(ctx context.Context, s Snapshot, options AssessmentOptions) {
	for i, p := range s.items("pods") {
		if ctx.Err() != nil {
			job.mu.Lock()
			job.status, job.message = "error", "Assessment cancelled or timed out; refresh to retry"
			job.mu.Unlock()
			return
		}
		risk := assessPod(p, s, options).Risk
		job.mu.Lock()
		job.pods[i].Risk = risk
		job.mu.Unlock()
	}
	job.mu.Lock()
	job.status = "complete"
	job.mu.Unlock()
}

func workloadKey(p PodView) string {
	if p.Ownership.Status == "resolved" && len(p.Ownership.Owners) > 0 {
		o := p.Ownership.Owners[len(p.Ownership.Owners)-1]
		return jsonText([]string{p.Namespace, strings.Split(o.APIVersion, "/")[0], o.Kind, o.Name})
	}
	return jsonText([]string{p.Namespace, "", "Pod", p.Name, p.UID})
}

func inventoryLess(a, b PodView, mode string) bool {
	reviewA, reviewB := a.Risk.Unknown > 0, b.Risk.Unknown > 0
	if mode == "review" && reviewA != reviewB {
		return reviewA
	}
	if mode != "name" && a.Risk.Score != b.Risk.Score {
		return a.Risk.Score > b.Risk.Score
	}
	if mode != "name" && reviewA != reviewB {
		return reviewA
	}
	return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
}

func (job *inventoryJob) page(q inventoryQuery) inventoryPage {
	job.mu.RLock()
	page := inventoryPage{Snapshot: job.id, CapturedAt: job.captured, ExpiresAt: job.expires, Status: job.status, Message: job.message, States: job.states, Pods: []PodView{}}
	pods := append([]PodView{}, job.pods...)
	job.mu.RUnlock()
	hidden := map[string]bool{}
	for _, key := range q.Hidden {
		hidden[key] = true
	}
	for _, p := range pods {
		if !strings.Contains(p.Name, q.Name) {
			continue
		}
		if hidden[workloadKey(p)] {
			page.Hidden++
			if !q.ShowHidden {
				continue
			}
		}
		page.Pods = append(page.Pods, p)
		page.Summary.Total++
		switch p.Risk.Level {
		case "critical":
			page.Summary.Critical++
		case "high":
			page.Summary.High++
		case "pending":
			page.Summary.Pending++
		}
		if p.Risk.Unknown > 0 {
			page.Summary.Review++
		}
	}
	mode := q.Sort
	if page.Status != "complete" {
		mode = "name"
	}
	sort.Slice(page.Pods, func(i, j int) bool { return inventoryLess(page.Pods[i], page.Pods[j], mode) })
	page.Total = len(page.Pods)
	page.Offset = min(q.Offset, page.Total)
	page.NextOffset = page.Offset + min(q.Limit, page.Total-page.Offset)
	page.HasMore = page.NextOffset < page.Total
	page.Pods = page.Pods[page.Offset:page.NextOffset]
	return page
}

func inventoryHandler(client *Client) http.HandlerFunc {
	store := &inventoryStore{client: client, jobs: map[string]*inventoryJob{}}
	context.AfterFunc(client.ctx, func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		for _, job := range store.jobs {
			job.cancel()
			if job.timer != nil {
				job.timer.Stop()
			}
		}
		store.jobs = map[string]*inventoryJob{}
	})
	return func(w http.ResponseWriter, r *http.Request) {
		q, err := parseInventoryQuery(w, r)
		if err != nil {
			problem(w, 400, err.Error())
			return
		}
		job, status, err := store.job(q)
		if err != nil {
			problem(w, status, err.Error())
			return
		}
		page := job.page(q)
		if q.Offset > 0 && page.Status != "complete" {
			problem(w, 409, "Assessment is pending; poll the first page before continuing")
			return
		}
		writeJSON(w, 200, page)
	}
}

func namespaceHandler(client *Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := client.cachedList(r.Context(), resources[0], "")
		names := []string{}
		for _, n := range c.Items {
			names = append(names, name(n))
		}
		sort.Strings(names)
		writeJSON(w, 200, map[string]any{"namespaces": names, "state": c.State})
	}
}
