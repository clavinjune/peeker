package explorer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"sync"
	"time"
)

var registryKinds = []string{"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

type registryEntry struct {
	Ref
	RegisteredAt string `json:"registeredAt"`
}

type registryStore struct {
	mu           sync.Mutex
	action       sync.Mutex
	client       *Client
	entries      map[string]registryEntry
	scans        map[string]*imageScan
	backups      map[string]string
	backupOwners map[string]Ref
	scanRunning  bool
}

type registryRequest struct {
	Operation string `json:"operation"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	Image     string `json:"image,omitempty"`
}

func registryResource(kind string) (resource, bool) {
	for _, allowed := range registryKinds {
		if kind == allowed {
			for _, r := range resources {
				if r.kind == kind {
					return r, true
				}
			}
		}
	}
	return resource{}, false
}

func resourcePath(r resource, ns, n string) string {
	base := "/apis/" + r.group + "/" + r.versions[0]
	if r.group == "" {
		base = "/api/" + r.versions[0]
	}
	if r.namespaced {
		base += "/namespaces/" + ns
	}
	base += "/" + r.plural
	if n != "" {
		base += "/" + n
	}
	return base
}

func workloadTemplate(o Object) Object {
	template := obj(at(o, "spec", "template"))
	if o["kind"] == "CronJob" {
		template = obj(at(o, "spec", "jobTemplate", "spec", "template"))
	}
	return Object{"apiVersion": "v1", "kind": "Pod", "metadata": Object{"namespace": namespace(o), "name": name(o) + "-template", "labels": at(template, "metadata", "labels"), "annotations": at(template, "metadata", "annotations")}, "spec": template["spec"]}
}

func ownedBy(o, workload Object, s Snapshot) bool {
	for _, owner := range ownership(o, s).Owners {
		if owner.UID != "" && owner.UID == uid(workload) && owner.Kind == text(workload["kind"]) {
			return true
		}
	}
	return false
}

func (store *registryStore) mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/registry", store.list)
	mux.HandleFunc("GET /api/registry/workload", store.detail)
	mux.HandleFunc("POST /api/registry/change", store.change)
	mux.HandleFunc("GET /api/registry/scan", store.scanResult)
	mux.HandleFunc("GET /api/registry/backup", store.backup)
}

func newRegistry(client *Client) *registryStore {
	return &registryStore{client: client, entries: map[string]registryEntry{}, scans: map[string]*imageScan{}, backups: map[string]string{}, backupOwners: map[string]Ref{}}
}

func (store *registryStore) list(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("namespace")
	if !validName(ns, true) {
		problem(w, 400, "Choose a namespace")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if r.URL.Query().Get("refresh") == "true" {
		store.client.invalidate()
	}
	s := store.client.snapshot(ctx, ns, false)
	rows := []Object{}
	podCounts, podRisks := workloadPodRisks(s, store.client.Assessment)
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, kind := range registryKinds {
		for _, workload := range s.items(ownerCollections[kind]) {
			entry, registered := store.entries[uid(workload)]
			risk := assessPod(workloadTemplate(workload), s, store.client.Assessment).Risk
			if live := podRisks[uid(workload)]; live.Score > risk.Score {
				risk = live
			}
			rows = append(rows, Object{"resource": ref(workload), "registered": registered, "registeredAt": entry.RegisteredAt, "pods": podCounts[uid(workload)], "risk": risk})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if a, b := rows[i]["risk"].(RiskSummary), rows[j]["risk"].(RiskSummary); a.Score != b.Score {
			return a.Score > b.Score
		}
		return rows[i]["resource"].(Ref).ID() < rows[j]["resource"].(Ref).ID()
	})
	entries := []registryEntry{}
	for _, entry := range store.entries {
		if entry.Namespace == ns {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID() < entries[j].ID() })
	backups := []Object{}
	for id, owner := range store.backupOwners {
		if owner.Namespace == ns {
			backups = append(backups, Object{"id": id, "resource": owner})
		}
	}
	writeJSON(w, 200, Object{"workloads": rows, "entries": entries, "states": s.states(), "actionsAvailable": store.client.registryContext != "", "backups": backups})
}

func workloadPodRisks(s Snapshot, options AssessmentOptions) (map[string]int, map[string]RiskSummary) {
	counts, risks := map[string]int{}, map[string]RiskSummary{}
	for _, pod := range s.items("pods") {
		risk := assessPod(pod, s, options).Risk
		for _, owner := range ownership(pod, s).Owners {
			if owner.UID == "" {
				continue
			}
			counts[owner.UID]++
			if old, ok := risks[owner.UID]; !ok || risk.Score > old.Score {
				risks[owner.UID] = risk
			}
		}
	}
	return counts, risks
}

func registryInput(r *http.Request) registryRequest {
	q := r.URL.Query()
	return registryRequest{Kind: q.Get("kind"), Namespace: q.Get("namespace"), Name: q.Get("name"), UID: q.Get("uid")}
}

func (store *registryStore) resolve(ctx context.Context, input registryRequest) (Object, error) {
	r, ok := registryResource(input.Kind)
	if !ok || !validName(input.Namespace, true) || !validName(input.Name, false) || input.UID == "" || len(input.UID) > 128 {
		return nil, errors.New("Invalid workload identity; select a controller from Registry")
	}
	o, err := store.client.get(ctx, resourcePath(r, input.Namespace, input.Name))
	if err != nil {
		return nil, err
	}
	if uid(o) != input.UID {
		return nil, errors.New("Workload UID changed; refresh and register its replacement")
	}
	o["kind"], o["apiVersion"] = r.kind, r.group+"/"+r.versions[0]
	return o, nil
}

func (store *registryStore) detail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	input := registryInput(r)
	o, err := store.resolve(ctx, input)
	if err != nil {
		problem(w, 409, err.Error())
		return
	}
	if r.URL.Query().Get("refresh") == "true" {
		store.client.invalidate()
	}
	s := store.client.snapshot(ctx, input.Namespace, true)
	store.mu.Lock()
	_, registered := store.entries[input.UID]
	scans := []imageScan{}
	for _, scan := range store.scans {
		if scan.UID == input.UID {
			summary := *scan
			summary.SBOM = nil
			scans = append(scans, summary)
		}
	}
	store.mu.Unlock()
	report := workloadReport(o, s, store.client.Assessment, registered, store.client.registryContext != "")
	report["scans"] = scans
	writeJSON(w, 200, report)
}

func decodeRegistry(w http.ResponseWriter, r *http.Request) (registryRequest, bool) {
	var input registryRequest
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Header.Get("Origin") != "http://"+r.Host || r.Header.Get("X-Peeker-Action") != "registry" || media != "application/json" || r.Header.Get("X-Peeker-Context") == "" {
		problem(w, 403, "Registry changes require same-origin JSON and context headers")
		return input, false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(&struct{}{}) != io.EOF {
		problem(w, 400, "Invalid Registry request")
		return input, false
	}
	return input, true
}

func (store *registryStore) change(w http.ResponseWriter, r *http.Request) {
	input, ok := decodeRegistry(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if input.Operation == "unregister" {
		store.mu.Lock()
		delete(store.entries, input.UID)
		store.mu.Unlock()
		writeJSON(w, 200, Object{"status": "unregistered"})
		return
	}
	o, err := store.resolve(ctx, input)
	if err != nil {
		problem(w, 409, err.Error())
		return
	}
	store.mu.Lock()
	_, registered := store.entries[input.UID]
	if input.Operation == "register" && (registered || len(store.entries) < 256) {
		store.entries[input.UID] = registryEntry{ref(o), time.Now().UTC().Format(time.RFC3339)}
		store.mu.Unlock()
		writeJSON(w, 200, Object{"status": "registered"})
		return
	}
	store.mu.Unlock()
	if !registered {
		problem(w, 409, "Register this workload first (maximum 256 entries per context session)")
		return
	}
	if input.Operation == "scan" {
		store.startScan(w, ctx, input, o)
		return
	}
	store.runAction(w, ctx, input, o)
}
