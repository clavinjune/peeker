package explorer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type actionResult struct {
	Status string   `json:"status"`
	Steps  []string `json:"steps"`
	Backup string   `json:"backup,omitempty"`
}

type mutationStatus int

func (status mutationStatus) Error() string {
	return fmt.Sprintf("Responder returned HTTP %d; action may be partial", status)
}

func (c *Client) mutate(ctx context.Context, method, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if method == "PATCH" {
		req.Header.Set("Content-Type", "application/json-patch+json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("Responder request failed; inspect cluster state before retrying")
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return mutationStatus(response.StatusCode)
	}
	return nil
}

func objectResource(o Object) (resource, error) {
	for _, r := range resources {
		if r.kind == text(o["kind"]) {
			return r, nil
		}
	}
	return resource{}, errors.New("Unsupported action resource")
}

func deleteObject(ctx context.Context, c *Client, o Object, propagation string) error {
	r, err := objectResource(o)
	if err != nil {
		return err
	}
	if uid(o) == "" || text(at(o, "metadata", "resourceVersion")) == "" {
		return errors.New("Missing UID or resourceVersion; refusing deletion")
	}
	return c.mutate(ctx, "DELETE", resourcePath(r, namespace(o), name(o)), Object{"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": propagation, "preconditions": Object{"uid": uid(o), "resourceVersion": at(o, "metadata", "resourceVersion")}})
}

func checkedPatch(ctx context.Context, c *Client, o Object, changes []Object) error {
	r, err := objectResource(o)
	if err != nil {
		return err
	}
	if uid(o) == "" || text(at(o, "metadata", "resourceVersion")) == "" {
		return errors.New("Missing identity preconditions; refusing patch")
	}
	patch := []Object{{"op": "test", "path": "/metadata/uid", "value": uid(o)}, {"op": "test", "path": "/metadata/resourceVersion", "value": at(o, "metadata", "resourceVersion")}}
	return c.mutate(ctx, "PATCH", resourcePath(r, namespace(o), name(o)), append(patch, changes...))
}

func (store *registryStore) runAction(w http.ResponseWriter, ctx context.Context, input registryRequest, o Object) {
	if input.Operation != "contain" && input.Operation != "orphan" && input.Operation != "kill" {
		problem(w, 400, "Unsupported Registry operation")
		return
	}
	if store.client.registryContext == "" {
		problem(w, 403, "Workload actions require a managed context and the peeker-responder identity")
		return
	}
	if !store.action.TryLock() {
		problem(w, 409, "A workload action is already running")
		return
	}
	defer store.action.Unlock()
	process, err := startResponder(ctx, store.client.registryContext)
	if err != nil {
		problem(w, 502, err.Error())
		return
	}
	defer process.stop()
	defer process.client.Close()
	result := actionResult{Status: "configured", Steps: []string{}}
	switch input.Operation {
	case "kill":
		err = deleteObject(ctx, process.client, o, "Foreground")
		if err == nil {
			result.Steps = append(result.Steps, "Foreground workload deletion requested. Kubernetes garbage collection is asynchronous; retained storage is not deleted by Peeker.")
		}
	case "orphan":
		err = store.orphan(ctx, process.client, o, &result)
	case "contain":
		err = store.contain(ctx, process.client, o, &result)
	}
	store.client.invalidate()
	if err != nil {
		result.Status = "partial-or-failed"
		result.Steps = append(result.Steps, err.Error())
		writeJSON(w, 409, result)
		return
	}
	writeJSON(w, 200, result)
}

func startResponder(ctx context.Context, name string) (*proxyProcess, error) {
	args := proxyArguments(name)
	args[1] = "--as=system:serviceaccount:peeker-system:peeker-responder"
	args[len(args)-1] = "--reject-methods=CONNECT,TRACE,OPTIONS,HEAD"
	return startProxy(ctx, args)
}

func (store *registryStore) orphan(ctx context.Context, c *Client, o Object, result *actionResult) error {
	store.client.invalidate()
	s := store.client.snapshot(ctx, namespace(o), false)
	for _, key := range []string{"pods", "replicasets", "jobs"} {
		if !s.available(key) {
			return errors.New("Orphaning requires complete Pod, ReplicaSet and Job inventories")
		}
	}
	children := []Object{}
	for _, key := range []string{"replicasets", "jobs"} {
		for _, child := range s.items(key) {
			if ownedBy(child, o, s) {
				children = append(children, child)
			}
		}
	}
	if err := deleteObject(ctx, c, o, "Orphan"); err != nil {
		return err
	}
	result.Steps = append(result.Steps, "Requested orphan deletion of "+text(o["kind"])+" "+name(o))
	for _, child := range children {
		if err := store.orphanChild(ctx, c, child); err != nil {
			return err
		}
		result.Steps = append(result.Steps, "Requested orphan deletion of "+text(child["kind"])+" "+name(child))
	}
	result.Steps = append(result.Steps, "Existing Pods can continue after garbage collection detaches owners. This stops controller-driven replacement for investigation; it is not isolation. Pods lose self-healing and can still exit. An external operator or GitOps reconciler may recreate controllers.")
	return nil
}

func (store *registryStore) orphanChild(ctx context.Context, c *Client, child Object) error {
	r, err := objectResource(child)
	if err != nil {
		return err
	}
	owners := map[string]bool{}
	for _, owner := range arr(at(child, "metadata", "ownerReferences")) {
		owners[text(obj(owner)["uid"])] = true
	}
	for attempt := 0; attempt < 4; attempt++ {
		current, err := store.client.get(ctx, resourcePath(r, namespace(child), name(child)))
		if err != nil {
			return err
		}
		if uid(current) != uid(child) {
			return errors.New("Intermediate controller was replaced; refusing to delete its replacement")
		}
		for _, owner := range arr(at(current, "metadata", "ownerReferences")) {
			if !owners[text(obj(owner)["uid"])] {
				return errors.New("Intermediate controller has a new owner; refusing deletion")
			}
		}
		current["kind"] = child["kind"]
		err = deleteObject(ctx, c, current, "Orphan")
		var status mutationStatus
		if !errors.As(err, &status) || status != mutationStatus(http.StatusConflict) || attempt == 3 {
			return err
		}
		// Orphan propagation asynchronously removes the parent reference and changes
		// resourceVersion. Refresh only on conflict, retaining UID/RV preconditions.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

func (store *registryStore) backup(w http.ResponseWriter, r *http.Request) {
	store.mu.Lock()
	data, ok := store.backups[r.URL.Query().Get("id")]
	store.mu.Unlock()
	if !ok {
		problem(w, 404, "Backup not found in this context session")
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="peeker-rbac-backup.yaml"`)
	io.WriteString(w, data)
}

func (store *registryStore) saveBackup(objects []Object, workload Ref, result *actionResult) error {
	var data strings.Builder
	for _, o := range objects {
		b, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			return err
		}
		data.WriteString("---\n")
		data.Write(b)
		data.WriteString("\n")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.backups) >= 32 || data.Len() > 4*1024*1024 {
		return errors.New("In-memory backup limit reached; refusing RBAC changes")
	}
	result.Backup = rand.Text()
	store.backups[result.Backup] = data.String()
	store.backupOwners[result.Backup] = workload
	return nil
}
