package explorer

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
)

func accountName(p Object) string {
	n := text(at(p, "spec", "serviceAccountName"))
	if n == "" {
		return "default"
	}
	return n
}

func identityShared(o Object, s Snapshot, account string) bool {
	if account == "default" || namespace(o) == "peeker-system" {
		return true
	}
	for _, p := range s.items("pods") {
		if namespace(p) == namespace(o) && accountName(p) == account && !ownedBy(p, o, s) {
			return true
		}
	}
	for _, key := range ownerCollections {
		for _, other := range s.items(key) {
			if namespace(other) == namespace(o) && uid(other) != uid(o) && !ownedBy(other, o, s) && accountName(workloadTemplate(other)) == account {
				return true
			}
		}
	}
	return false
}

func workloadAccounts(o Object, s Snapshot) map[string]bool {
	accounts := map[string]bool{accountName(workloadTemplate(o)): true}
	for _, p := range s.items("pods") {
		if ownedBy(p, o, s) {
			accounts[accountName(p)] = true
		}
	}
	return accounts
}

func bindsAccounts(binding Object, ns string, accounts map[string]bool) bool {
	for account, enabled := range accounts {
		if enabled && boundServiceAccount(binding, ns, account) {
			return true
		}
	}
	return false
}

func rbacBackupObjects(o Object, s Snapshot) []Object {
	result := []Object{}
	seen := map[string]bool{}
	accounts := workloadAccounts(o, s)
	for _, key := range []string{"rolebindings", "clusterrolebindings"} {
		for _, binding := range s.items(key) {
			if !bindsAccounts(binding, namespace(o), accounts) {
				continue
			}
			result = append(result, binding)
			roleKey, ns := "clusterroles", ""
			if at(binding, "roleRef", "kind") == "Role" {
				roleKey, ns = "roles", namespace(binding)
			}
			role, found := s.find(roleKey, ns, text(at(binding, "roleRef", "name")))
			if found && !seen[ref(role).ID()] {
				result = append(result, role)
				seen[ref(role).ID()] = true
			}
		}
	}
	return result
}

func revokeDirectBindings(ctx context.Context, c *Client, o Object, s Snapshot, result *actionResult) error {
	accounts := workloadAccounts(o, s)
	for account := range accounts {
		if identityShared(o, s, account) {
			accounts[account] = false
			result.Steps = append(result.Steps, "RBAC retained for "+account+": shared, default or Peeker ServiceAccount; revocation could affect other workloads.")
		}
	}
	for _, key := range []string{"rolebindings", "clusterrolebindings"} {
		for _, binding := range s.items(key) {
			if !bindsAccounts(binding, namespace(o), accounts) {
				continue
			}
			kept := []any{}
			removed := false
			for _, v := range arr(binding["subjects"]) {
				subject := obj(v)
				one := Object{"metadata": binding["metadata"], "subjects": []any{v}}
				if subject["kind"] != "Group" && bindsAccounts(one, namespace(o), accounts) {
					removed = true
				} else {
					kept = append(kept, v)
				}
			}
			if !removed {
				result.Steps = append(result.Steps, "Shared group grant retained: "+ref(binding).ID())
				continue
			}
			var err error
			if len(kept) == 0 {
				err = deleteObject(ctx, c, binding, "Background")
			} else {
				err = checkedPatch(ctx, c, binding, []Object{{"op": "replace", "path": "/subjects", "value": kept}})
			}
			if err != nil {
				return err
			}
			result.Steps = append(result.Steps, "Removed direct ServiceAccount grant from "+ref(binding).ID())
		}
	}
	result.Steps = append(result.Steps, "Role definitions retained: bindings grant access, and roles can be shared or aggregated. Group grants, other authorizers and existing credentials may still permit access.")
	return nil
}

func containmentPods(o Object, s Snapshot) ([]Object, error) {
	for _, key := range []string{"pods", "ciliumnetworkpolicies", "ciliumendpoints", "roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
		if !s.available(key) {
			return nil, errors.New("Containment requires complete Cilium endpoint/policy, Pod and RBAC inventories: " + key)
		}
	}
	for _, key := range ownerCollections {
		if !s.available(key) {
			return nil, errors.New("Containment requires complete controller inventories: " + key)
		}
	}
	pods := []Object{}
	for _, p := range s.items("pods") {
		if !ownedBy(p, o, s) {
			continue
		}
		if at(p, "spec", "hostNetwork") == true {
			return nil, errors.New("Host-network Pods cannot be isolated without potentially affecting their host")
		}
		endpoint, found := s.find("ciliumendpoints", namespace(p), name(p))
		managed := false
		for _, v := range arr(at(endpoint, "metadata", "ownerReferences")) {
			owner := obj(v)
			if owner["kind"] == "Pod" && owner["uid"] == uid(p) {
				managed = true
			}
		}
		if !found || !managed {
			return nil, errors.New("Every target Pod must have a UID-matched CiliumEndpoint; Kubernetes NetworkPolicy alone cannot override existing allows")
		}
		pods = append(pods, p)
	}
	if len(pods) == 0 {
		return nil, errors.New("No current Pods to contain")
	}
	if len(pods) > 100 {
		return nil, errors.New("Containment is limited to 100 current Pods per action")
	}
	return pods, nil
}

func containmentSpec(token string) Object {
	return Object{"endpointSelector": Object{"matchLabels": Object{"peeker.dev/containment": token}}, "ingressDeny": []any{Object{"fromEntities": []string{"all"}}}, "egressDeny": []any{Object{"toEntities": []string{"all"}}}}
}

func uncontainedPods(pods []Object, s Snapshot) ([]Object, error) {
	remaining := []Object{}
	for _, p := range pods {
		token := text(labels(p)["peeker.dev/containment"])
		if token == "" {
			remaining = append(remaining, p)
			continue
		}
		policy, found := s.find("ciliumnetworkpolicies", namespace(p), "peeker-contain-"+token)
		if !found || jsonText(policy["spec"]) != jsonText(containmentSpec(token)) {
			return nil, errors.New("Existing containment label has no matching Peeker deny policy; inspect it before retrying")
		}
	}
	return remaining, nil
}

func (store *registryStore) contain(ctx context.Context, c *Client, o Object, result *actionResult) error {
	store.client.invalidate()
	s := store.client.snapshot(ctx, namespace(o), true)
	pods, err := containmentPods(o, s)
	if err != nil {
		return err
	}
	pods, err = uncontainedPods(pods, s)
	if err != nil {
		return err
	}
	if err = store.saveBackup(rbacBackupObjects(o, s), ref(o), result); err != nil {
		return err
	}
	if len(pods) == 0 {
		result.Steps = append(result.Steps, "All current Pods already select matching Peeker deny configurations; enforcement still requires cluster verification.")
		return revokeDirectBindings(ctx, c, o, s, result)
	}
	token := strings.ToLower(rand.Text())
	key := "peeker.dev/containment"
	policy := Object{"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": Object{"name": "peeker-contain-" + token, "namespace": namespace(o)}, "spec": containmentSpec(token)}
	if err = c.mutate(ctx, "POST", "/apis/cilium.io/v2/namespaces/"+namespace(o)+"/ciliumnetworkpolicies", policy); err != nil {
		return err
	}
	result.Steps = append(result.Steps, "Created Cilium deny policy "+name(policy)+"; RBAC YAML backup is available for download.")
	for _, p := range pods {
		newLabels := Object{}
		for k, v := range labels(p) {
			newLabels[k] = v
		}
		if newLabels[key] != nil {
			return errors.New("Pod already has a containment label; inspect the existing policy before retrying")
		}
		newLabels[key] = token
		if err = checkedPatch(ctx, c, p, []Object{{"op": "add", "path": "/metadata/labels", "value": newLabels}}); err != nil {
			return err
		}
		result.Steps = append(result.Steps, "Selected existing Pod "+name(p)+" for ingress/egress deny without changing its spec")
	}
	result.Steps = append(result.Steps, "Deny configuration targets only these current Pod UIDs. Future/replacement Pods require another action. Cilium enforcement and existing connections must be verified; network-dependent probes can react to isolation.")
	return revokeDirectBindings(ctx, c, o, s, result)
}
