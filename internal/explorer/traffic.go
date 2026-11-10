package explorer

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const maxTrafficEdges = 64

type accessRecord struct {
	Start    string  `json:"start_time"`
	Cluster  string  `json:"upstream_cluster"`
	Upstream string  `json:"upstream_host"`
	Remote   string  `json:"downstream_direct_remote_address"`
	Protocol string  `json:"protocol"`
	Code     int     `json:"response_code"`
	Flags    string  `json:"response_flags"`
	Duration float64 `json:"duration"`
}

func parseAccessRecord(line []byte) (accessRecord, bool) {
	var wire struct {
		accessRecord
		Code     *int     `json:"response_code"`
		Duration *float64 `json:"duration"`
	}
	if json.Unmarshal(line, &wire) != nil || wire.Code == nil || wire.Duration == nil {
		return accessRecord{}, false
	}
	record := wire.accessRecord
	record.Code, record.Duration = *wire.Code, *wire.Duration
	_, err := time.Parse(time.RFC3339Nano, record.Start)
	protocol := record.Protocol == "HTTP/1.0" || record.Protocol == "HTTP/1.1" || record.Protocol == "HTTP/2" || record.Protocol == "HTTP/3"
	direction := strings.HasPrefix(record.Cluster, "inbound|") || strings.HasPrefix(record.Cluster, "outbound|")
	return record, err == nil && protocol && direction && record.Code >= 0 && record.Code <= 599 && record.Duration >= 0 && record.Duration <= 86400000
}

type trafficCount struct {
	Peer     Ref
	Inbound  bool
	Requests int
	Errors   int
	Duration float64
}

type trafficView struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	Started  string `json:"startedAt"`
	Requests int    `json:"requests"`
	Errors   int    `json:"errors"`
	Ignored  int    `json:"ignored"`
	Dropped  int    `json:"dropped"`
	Graph    Graph  `json:"graph"`
}

type trafficAggregate struct {
	pod   Ref
	peers map[string]Ref
	edges map[string]*trafficCount
	view  trafficView
}

func newTrafficAggregate(pod Object, pods []Object) *trafficAggregate {
	a := &trafficAggregate{pod: ref(pod), peers: map[string]Ref{}, edges: map[string]*trafficCount{}, view: trafficView{Started: time.Now().UTC().Format(time.RFC3339)}}
	for _, p := range pods {
		ips := append([]any{map[string]any{"ip": at(p, "status", "podIP")}}, arr(at(p, "status", "podIPs"))...)
		for _, value := range ips {
			ip := net.ParseIP(text(obj(value)["ip"]))
			if ip == nil {
				continue
			}
			key, peer := ip.String(), ref(p)
			if prior, exists := a.peers[key]; exists && prior.UID != peer.UID {
				peer = Ref{}
			}
			a.peers[key] = peer
		}
	}
	return a
}

func (a *trafficAggregate) add(record accessRecord) {
	inbound := strings.HasPrefix(record.Cluster, "inbound|")
	address := record.Upstream
	if inbound {
		address = record.Remote
	}
	host, _, _ := net.SplitHostPort(address)
	peer := a.peers[net.ParseIP(host).String()]
	if peer.UID == a.pod.UID {
		peer = Ref{}
	}
	key := fmt.Sprintf("%t/%s", inbound, peer.ID())
	count, exists := a.edges[key]
	if !exists {
		if len(a.edges) >= maxTrafficEdges {
			a.view.Dropped++
			return
		}
		count = &trafficCount{Peer: peer, Inbound: inbound}
		a.edges[key] = count
	}
	count.Requests++
	a.view.Requests++
	count.Duration += record.Duration
	if record.Code == 0 || record.Code >= 400 || (record.Flags != "" && record.Flags != "-") {
		count.Errors++
		a.view.Errors++
	}
}

func (a *trafficAggregate) snapshot(status, message string) trafficView {
	view := a.view
	view.Status, view.Message = status, message
	view.Graph = Graph{Nodes: []Node{}, Edges: []Edge{}}
	center := view.Graph.resource(a.pod)
	keys := make([]string, 0, len(a.edges))
	for key := range a.edges {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count := a.edges[key]
		peer := ""
		if count.Peer.Name != "" {
			peer = view.Graph.resource(count.Peer)
		} else {
			peer = view.Graph.node(fmt.Sprintf("unknown/%t", count.Inbound), "Unknown peer", "Unknown", nil)
		}
		from, to := center, peer
		if count.Inbound {
			from, to = peer, center
		}
		label := fmt.Sprintf("%d requests · %d errors · %.1f ms mean", count.Requests, count.Errors, count.Duration/float64(count.Requests))
		view.Graph.edge(from, to, "observed", label, Evidence{a.pod, "istio-proxy structured access logs", label + ". Completed HTTP requests observed on this sidecar. Peer identity uses unique IP matches from the inventory at stream start; unknown peers are not inferred from request headers."})
	}
	return view
}
