package explorer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type resource struct {
	key, group, plural, kind string
	versions                 []string
	namespaced               bool
}

var resources = []resource{
	{"namespaces", "", "namespaces", "Namespace", []string{"v1"}, false},
	{"pods", "", "pods", "Pod", []string{"v1"}, true},
	{"serviceaccounts", "", "serviceaccounts", "ServiceAccount", []string{"v1"}, true},
	{"roles", "rbac.authorization.k8s.io", "roles", "Role", []string{"v1"}, true},
	{"rolebindings", "rbac.authorization.k8s.io", "rolebindings", "RoleBinding", []string{"v1"}, true},
	{"clusterroles", "rbac.authorization.k8s.io", "clusterroles", "ClusterRole", []string{"v1"}, false},
	{"clusterrolebindings", "rbac.authorization.k8s.io", "clusterrolebindings", "ClusterRoleBinding", []string{"v1"}, false},
	{"services", "", "services", "Service", []string{"v1"}, true},
	{"replicationcontrollers", "", "replicationcontrollers", "ReplicationController", []string{"v1"}, true},
	{"replicasets", "apps", "replicasets", "ReplicaSet", []string{"v1"}, true},
	{"deployments", "apps", "deployments", "Deployment", []string{"v1"}, true},
	{"statefulsets", "apps", "statefulsets", "StatefulSet", []string{"v1"}, true},
	{"daemonsets", "apps", "daemonsets", "DaemonSet", []string{"v1"}, true},
	{"jobs", "batch", "jobs", "Job", []string{"v1"}, true},
	{"cronjobs", "batch", "cronjobs", "CronJob", []string{"v1"}, true},
	{"networkpolicies", "networking.k8s.io", "networkpolicies", "NetworkPolicy", []string{"v1"}, true},
	{"ingresses", "networking.k8s.io", "ingresses", "Ingress", []string{"v1"}, true},
	{"endpointslices", "discovery.k8s.io", "endpointslices", "EndpointSlice", []string{"v1"}, true},
	{"ciliumnetworkpolicies", "cilium.io", "ciliumnetworkpolicies", "CiliumNetworkPolicy", []string{"v2"}, true},
	{"ciliumendpoints", "cilium.io", "ciliumendpoints", "CiliumEndpoint", []string{"v2"}, true},
	{"ciliumclusterwidenetworkpolicies", "cilium.io", "ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy", []string{"v2"}, false},
	{"virtualservices", "networking.istio.io", "virtualservices", "VirtualService", []string{"v1", "v1beta1"}, true},
	{"istiogateways", "networking.istio.io", "gateways", "Gateway", []string{"v1", "v1beta1"}, true},
	{"destinationrules", "networking.istio.io", "destinationrules", "DestinationRule", []string{"v1", "v1beta1"}, true},
	{"httproutes", "gateway.networking.k8s.io", "httproutes", "HTTPRoute", []string{"v1", "v1beta1"}, true},
	{"tcproutes", "gateway.networking.k8s.io", "tcproutes", "TCPRoute", []string{"v1alpha2", "v1"}, true},
	{"gateways", "gateway.networking.k8s.io", "gateways", "Gateway", []string{"v1", "v1beta1"}, true},
	{"referencegrants", "gateway.networking.k8s.io", "referencegrants", "ReferenceGrant", []string{"v1beta1", "v1"}, true},
}

type Client struct {
	registryContext string
	http            *http.Client
	cancel          context.CancelFunc
	cache           map[string]*collectionRead
	reads           chan struct{}
	ctx             context.Context
	base            string
	cacheMu         sync.Mutex
	pending         int
	Assessment      AssessmentOptions
}

func NewClient(raw string) (*Client, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid proxy URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("proxy URL must be an HTTP loopback IP origin, for example http://127.0.0.1:8001")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{base: strings.TrimRight(raw, "/"), http: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Assessment: AssessmentOptions{ExpectIstio: true}, ctx: ctx, cancel: cancel, cache: map[string]*collectionRead{}, reads: make(chan struct{}, 6)}, nil
}

type readError struct {
	status  int
	message string
}

func (e readError) Error() string { return e.message }
func (c *Client) get(ctx context.Context, path string) (Object, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, readError{0, "Cannot reach kubectl proxy. Reconnect the selected context or check your external proxy."}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, readError{response.StatusCode, fmt.Sprintf("Kubernetes read returned HTTP %d", response.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024+1))
	if err != nil || len(body) > 16*1024*1024 {
		return nil, readError{0, "Resource response incomplete or exceeds 16 MiB"}
	}
	var o Object
	if json.Unmarshal(body, &o) != nil {
		return nil, readError{0, "Proxy returned invalid Kubernetes JSON"}
	}
	return o, nil
}
func failed(key string, err error, discovery bool) Collection {
	status := "error"
	var re readError
	if errors.As(err, &re) {
		switch re.status {
		case 401, 403:
			status = "denied"
		case 404:
			if discovery {
				status = "missing-api"
			}
		}
	}
	return Collection{Items: []Object{}, State: State{key, status, err.Error()}}
}
func (c *Client) list(ctx context.Context, r resource, ns string) Collection {
	base := ""
	for _, version := range r.versions {
		base = "/apis/" + r.group + "/" + version
		if r.group == "" {
			base = "/api/" + version
		}
		discovery, err := c.get(ctx, base)
		if err != nil {
			var re readError
			if errors.As(err, &re) && re.status == 404 {
				base = ""
				continue
			}
			return failed(r.key, err, true)
		}
		found := false
		for _, v := range arr(discovery["resources"]) {
			if obj(v)["name"] == r.plural {
				found = true
			}
		}
		if found {
			break
		}
		base = ""
	}
	if base == "" {
		return Collection{Items: []Object{}, State: State{r.key, "missing-api", "API not installed or no supported version served"}}
	}
	if ns != "" && r.namespaced {
		base += "/namespaces/" + ns
	}
	base += "/" + r.plural
	items := []Object{}
	continuation := ""
	for page := 0; page < 40; page++ {
		query := url.Values{"limit": {"500"}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		result, err := c.get(ctx, base+"?"+query.Encode())
		if err != nil {
			return failed(r.key, err, false)
		}
		if _, ok := result["items"].([]any); !ok {
			return failed(r.key, errors.New("Kubernetes list has no items array"), false)
		}
		for _, v := range arr(result["items"]) {
			o := obj(v)
			if o == nil {
				return failed(r.key, errors.New("Kubernetes list contains an invalid resource"), false)
			}
			o["kind"] = r.kind
			o["apiVersion"] = strings.TrimPrefix(strings.TrimPrefix(base, "/apis/"), "/api/")
			o["apiVersion"] = strings.Split(text(o["apiVersion"]), "/namespaces/")[0]
			o["apiVersion"] = strings.TrimSuffix(text(o["apiVersion"]), "/"+r.plural)
			items = append(items, o)
			if len(items) > 20000 {
				return failed(r.key, errors.New("List exceeds 20,000 resources; results not treated as complete"), false)
			}
		}
		continuation = text(at(result, "metadata", "continue"))
		if continuation == "" {
			return Collection{Items: items, State: State{r.key, "available", ""}}
		}
	}
	return failed(r.key, errors.New("List exceeds 20,000 resources; results not treated as complete"), false)
}
func (c *Client) snapshot(ctx context.Context, ns string, details bool) Snapshot {
	s := Snapshot{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range resources {
		if !details && !inventoryCollections[r.key] {
			if _, ok := ownerCollections[r.kind]; !ok {
				continue
			}
		}
		wg.Add(1)
		go func(r resource) {
			defer wg.Done()
			resourceNS := ns
			if rbacCollections[r.key] {
				resourceNS = ""
			}
			collection := c.cachedList(ctx, r, resourceNS)
			mu.Lock()
			s[r.key] = collection
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return indexedSnapshot(s)
}

var inventoryCollections = map[string]bool{"pods": true, "namespaces": true, "serviceaccounts": true, "roles": true, "rolebindings": true, "clusterroles": true, "clusterrolebindings": true, "networkpolicies": true, "ciliumnetworkpolicies": true, "ciliumclusterwidenetworkpolicies": true}
