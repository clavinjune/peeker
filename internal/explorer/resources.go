package explorer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Object map[string]any

func obj(v any) Object {
	if m, ok := v.(Object); ok {
		return m
	}
	m, _ := v.(map[string]any)
	return m
}
func arr(v any) []any   { a, _ := v.([]any); return a }
func text(v any) string { s, _ := v.(string); return s }
func at(o Object, keys ...string) any {
	var v any = map[string]any(o)
	for _, k := range keys {
		v = obj(v)[k]
	}
	return v
}
func name(o Object) string      { return text(at(o, "metadata", "name")) }
func namespace(o Object) string { return text(at(o, "metadata", "namespace")) }
func uid(o Object) string       { return text(at(o, "metadata", "uid")) }
func labels(o Object) Object    { return obj(at(o, "metadata", "labels")) }
func jsonText(v any) string     { b, _ := json.Marshal(v); return string(b) }

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func validName(s string, ns bool) bool {
	if len(s) == 0 || len(s) > 253 || (ns && len(s) > 63) {
		return false
	}
	parts := strings.Split(s, ".")
	if ns && len(parts) != 1 {
		return false
	}
	for _, p := range parts {
		if len(p) > 63 || !dnsLabel.MatchString(p) {
			return false
		}
	}
	return true
}

type Ref struct {
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
}

func ref(o Object) Ref {
	return Ref{text(o["kind"]), namespace(o), name(o), uid(o), text(o["apiVersion"])}
}
func (r Ref) ID() string {
	kind := r.Kind
	if group, _, found := strings.Cut(r.APIVersion, "/"); found {
		kind += "." + group
	}
	return kind + "/" + r.Namespace + "/" + r.Name
}

type State struct {
	Resource string `json:"resource"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
}
type Collection struct {
	Items []Object
	State State
}
type Snapshot map[string]Collection

func (s Snapshot) items(key string) []Object { return s[key].Items }
func (s Snapshot) available(key string) bool { return s[key].State.Status == "available" }
func (s Snapshot) states() []State {
	out := make([]State, 0, len(s))
	for _, c := range s {
		out = append(out, c.State)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}
func (s Snapshot) find(key, ns, n string) (Object, bool) {
	for _, o := range s.items(key) {
		if namespace(o) == ns && name(o) == n {
			return o, true
		}
	}
	return nil, false
}

type Evidence struct {
	Resource    Ref    `json:"resource"`
	Field       string `json:"field"`
	Description string `json:"description"`
}
type Edge struct {
	ID       string     `json:"id"`
	From     string     `json:"from"`
	To       string     `json:"to"`
	Status   string     `json:"status"`
	Label    string     `json:"label"`
	Evidence []Evidence `json:"evidence"`
}
type Node struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	Resource *Ref   `json:"resource,omitempty"`
}
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

func (g *Graph) node(id, label, kind string, r *Ref) string {
	for _, n := range g.Nodes {
		if n.ID == id {
			return id
		}
	}
	g.Nodes = append(g.Nodes, Node{id, label, kind, r})
	return id
}
func (g *Graph) resource(r Ref) string {
	return g.node(r.ID(), r.Kind+" "+r.Namespace+"/"+r.Name, r.Kind, &r)
}
func (g *Graph) edge(from, to, status, label string, evidence ...Evidence) {
	g.Edges = append(g.Edges, Edge{fmt.Sprintf("edge-%d", len(g.Edges)), from, to, status, label, evidence})
}

type OwnerChain struct {
	Owners  []Ref  `json:"owners"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

var ownerCollections = map[string]string{"ReplicaSet": "replicasets", "Deployment": "deployments", "StatefulSet": "statefulsets", "DaemonSet": "daemonsets", "Job": "jobs", "CronJob": "cronjobs", "ReplicationController": "replicationcontrollers"}

func ownership(pod Object, s Snapshot) OwnerChain {
	chain := OwnerChain{Owners: []Ref{}, Status: "standalone"}
	current := pod
	seen := map[string]bool{uid(pod): true}
	for depth := 0; depth < 16; depth++ {
		var controlling []Object
		for _, v := range arr(at(current, "metadata", "ownerReferences")) {
			o := obj(v)
			if o["controller"] == true {
				controlling = append(controlling, o)
			}
		}
		if len(controlling) == 0 {
			if len(chain.Owners) > 0 {
				chain.Status = "resolved"
			}
			return chain
		}
		if len(controlling) != 1 {
			chain.Status = "unresolved"
			chain.Message = "Multiple controlling owner references"
			return chain
		}
		o := controlling[0]
		r := Ref{text(o["kind"]), namespace(pod), text(o["name"]), text(o["uid"]), text(o["apiVersion"])}
		chain.Owners = append(chain.Owners, r)
		chain.Status = "unresolved"
		key, supported := ownerCollections[r.Kind]
		if !supported {
			chain.Message = "Controlling kind is referenced but not supported for traversal"
			return chain
		}
		if !s.available(key) {
			chain.Message = "Cannot read " + key + ": " + s[key].State.Status
			return chain
		}
		next, found := s.find(key, r.Namespace, r.Name)
		if !found || r.UID == "" || uid(next) != r.UID {
			chain.Message = "Owner missing or UID does not match"
			return chain
		}
		if seen[r.UID] {
			chain.Message = "Ownership cycle"
			return chain
		}
		seen[r.UID] = true
		current = next
	}
	chain.Status = "unresolved"
	chain.Message = "Ownership depth limit reached"
	return chain
}

type PodView struct {
	Ref
	Labels     Object      `json:"labels"`
	Node       string      `json:"node"`
	Phase      string      `json:"phase"`
	IP         string      `json:"ip"`
	Sidecar    bool        `json:"sidecar"`
	Ready      int         `json:"ready"`
	Containers int         `json:"containers"`
	Ownership  OwnerChain  `json:"ownership"`
	Risk       RiskSummary `json:"risk"`
}

func podView(p Object, s Snapshot) PodView {
	v := PodView{Ref: ref(p), Labels: labels(p), Node: text(at(p, "spec", "nodeName")), Phase: text(at(p, "status", "phase")), IP: text(at(p, "status", "podIP")), Ownership: ownership(p, s)}
	for _, c := range arr(at(p, "spec", "containers")) {
		v.Containers++
		if text(obj(c)["name"]) == "istio-proxy" {
			v.Sidecar = true
		}
	}
	for _, c := range arr(at(p, "status", "containerStatuses")) {
		if obj(c)["ready"] == true {
			v.Ready++
		}
	}
	for _, c := range arr(at(p, "spec", "initContainers")) {
		if obj(c)["restartPolicy"] == "Always" {
			v.Containers++
			if obj(c)["name"] == "istio-proxy" {
				v.Sidecar = true
			}
		}
	}
	for _, c := range arr(at(p, "status", "initContainerStatuses")) {
		if obj(c)["ready"] == true && obj(c)["name"] == "istio-proxy" {
			v.Ready++
		}
	}
	return v
}
