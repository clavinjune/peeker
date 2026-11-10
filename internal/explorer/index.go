package explorer

import "sync"

type peerResult struct {
	err                error
	label, description string
}

type grantResult struct {
	grants []permissionGrant
	gaps   []Evidence
}

type resourceIndex struct {
	names      map[string]Object
	namespaces map[string][]Object
	subjects   map[string][]Object
	peers      map[string]peerResult
	grants     map[string]grantResult
	scope      string
	mu         sync.Mutex
}

func indexCollection(c Collection, scope string) Collection {
	x := &resourceIndex{names: map[string]Object{}, namespaces: map[string][]Object{}, subjects: map[string][]Object{}, scope: scope}
	for _, o := range c.Items {
		x.names[namespace(o)+"/"+name(o)] = o
		x.namespaces[namespace(o)] = append(x.namespaces[namespace(o)], o)
		for _, value := range arr(o["subjects"]) {
			subject := obj(value)
			key := bindingSubject(subject, namespace(o))
			if key != "" {
				x.subjects[key] = append(x.subjects[key], o)
			}
		}
	}
	c.index = x
	return c
}

func bindingSubject(subject Object, ns string) string {
	switch text(subject["kind"]) {
	case "ServiceAccount":
		if text(subject["apiGroup"]) != "" {
			return ""
		}
		if value := text(subject["namespace"]); value != "" {
			ns = value
		}
		return "User/system:serviceaccount:" + ns + ":" + text(subject["name"])
	case "User", "Group":
		if subject["apiGroup"] == "rbac.authorization.k8s.io" {
			return text(subject["kind"]) + "/" + text(subject["name"])
		}
	}
	return ""
}

func indexedSnapshot(s Snapshot) Snapshot {
	for key, c := range s {
		if c.index == nil {
			c = indexCollection(c, "")
		}
		if key == "pods" {
			x := c.index
			c.index = &resourceIndex{names: x.names, namespaces: x.namespaces, scope: x.scope, peers: map[string]peerResult{}}
		}
		if key == "rolebindings" {
			x := c.index
			c.index = &resourceIndex{names: x.names, namespaces: x.namespaces, subjects: x.subjects, grants: map[string]grantResult{}}
		}
		s[key] = c
	}
	return s
}

func (s Snapshot) inNamespace(key, ns string) []Object {
	if x := s[key].index; x != nil {
		return x.namespaces[ns]
	}
	items := []Object{}
	for _, o := range s.items(key) {
		if namespace(o) == ns {
			items = append(items, o)
		}
	}
	return items
}

func (s Snapshot) bindings(key, ns, account string) []Object {
	x := s[key].index
	if x == nil {
		return s.items(key)
	}
	items := []Object{}
	seen := map[string]bool{}
	for _, identity := range []string{"User/system:serviceaccount:" + ns + ":" + account, "Group/system:serviceaccounts", "Group/system:serviceaccounts:" + ns, "Group/system:authenticated"} {
		for _, o := range x.subjects[identity] {
			id := namespace(o) + "/" + name(o)
			if !seen[id] {
				items = append(items, o)
				seen[id] = true
			}
		}
	}
	return items
}

func cachedPeerDescription(peer Object, ns string, s Snapshot) (string, string, error) {
	x := s["pods"].index
	if x == nil || x.peers == nil {
		return peerDescription(peer, ns, s)
	}
	key := ns + "/" + jsonText(peer)
	x.mu.Lock()
	defer x.mu.Unlock()
	if result, ok := x.peers[key]; ok {
		return result.label, result.description, result.err
	}
	label, description, err := peerDescription(peer, ns, s)
	if len(x.peers) < 4096 {
		x.peers[key] = peerResult{err, label, description}
	}
	return label, description, err
}
