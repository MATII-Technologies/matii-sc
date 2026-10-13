package operator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MATII-Technologies/matii-sc/go/internal/kube"
)

type fakeKube struct {
	mu        sync.Mutex
	items     []map[string]any
	secrets   map[string]map[string]any // name -> object
	statuses  []map[string]any
	restarts  []string
	tokenReqs []string
	applies   int
}

func (f *fakeKube) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		p := r.URL.Path
		switch {
		case r.Method == "GET" && p == "/apis/secrets.matii.io/v1alpha1/matiisecrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": f.items})
		case r.Method == "POST" && strings.HasSuffix(p, "/token"):
			f.tokenReqs = append(f.tokenReqs, p)
			if !strings.Contains(string(body), `"matii-secret-service"`) {
				t.Errorf("token request without audience: %s", body)
			}
			_, _ = w.Write([]byte(`{"status":{"token":"k8s-jwt"}}`))
		case strings.HasPrefix(p, "/api/v1/namespaces/payments/secrets/"):
			name := strings.TrimPrefix(p, "/api/v1/namespaces/payments/secrets/")
			if r.Method == "GET" {
				obj, ok := f.secrets[name]
				if !ok {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"message":"not found"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(obj)
				return
			}
			if r.Header.Get("Content-Type") != "application/apply-patch+yaml" || r.URL.Query().Get("fieldManager") != "matii-operator" {
				t.Errorf("secret written without server-side apply")
			}
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.secrets[name] = obj
			f.applies++
		case strings.HasSuffix(p, "/status"):
			var patch map[string]map[string]any
			_ = json.Unmarshal(body, &patch)
			f.statuses = append(f.statuses, patch["status"])
		case strings.HasPrefix(p, "/apis/apps/v1/"):
			f.restarts = append(f.restarts, p)
		default:
			t.Errorf("unexpected %s %s", r.Method, p)
			w.WriteHeader(500)
		}
	})
}

func fakeSecretService(t *testing.T, values *map[string]string) *httptest.Server {
	raw, _ := os.ReadFile("vectors_test.json")
	var v struct {
		Token           string `json:"token"`
		WrappedKeyShare string `json:"wrapped_key_share"`
	}
	_ = json.Unmarshal(raw, &v)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identities/external/v1/oidc/auth/":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"k8s-jwt"`) || !strings.Contains(string(body), `"sa-123"`) {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"authentication":{"token":"` + v.Token + `","TTL":600}}`))
		case "/secrets/tokens/":
			_, _ = w.Write([]byte(`{"wrapped_key_share":"` + v.WrappedKeyShare + `","apps":[{"id":"a1","name":"Payments","encryption":"SSE","environment_keys":[{"environment":{"id":"e1","name":"production"}}]}]}`))
		case "/v1/secrets/":
			var items []map[string]any
			for k, val := range *values {
				items = append(items, map[string]any{"key": k, "value": val, "path": "/"})
			}
			_ = json.NewEncoder(w).Encode(items)
		default:
			w.WriteHeader(404)
		}
	}))
}

func resource(secretName string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": "payments", "namespace": "payments", "uid": "uid-1", "generation": 1},
		"spec": map[string]any{
			"serviceAccountId": "sa-123", "kubernetesServiceAccount": "reader", "app": "Payments",
			"env": "production", "secretName": secretName,
			"rolloutRestart": []map[string]string{{"kind": "Deployment", "name": "api"}},
		},
	}
}

func setup(t *testing.T, values *map[string]string) (*Operator, *fakeKube) {
	fk := &fakeKube{secrets: map[string]map[string]any{}}
	kubeSrv := httptest.NewServer(fk.handler(t))
	t.Cleanup(kubeSrv.Close)
	svc := fakeSecretService(t, values)
	t.Cleanup(svc.Close)
	op := New(Config{APIBase: svc.URL, Kube: &kube.Client{Base: kubeSrv.URL, HTTP: kubeSrv.Client()}})
	return op, fk
}

func TestSyncCreatesSecretAndRestartsOnChange(t *testing.T) {
	values := map[string]string{"DB_URL": "postgres://x", "API_KEY": "k1"}
	op, fk := setup(t, &values)
	fk.items = []map[string]any{resource("payments-secrets")}

	if err := op.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	obj := fk.secrets["payments-secrets"]
	data := obj["data"].(map[string]any)
	decoded, _ := base64.StdEncoding.DecodeString(data["DB_URL"].(string))
	if string(decoded) != "postgres://x" {
		t.Fatalf("data: %v", data)
	}
	meta := obj["metadata"].(map[string]any)
	if meta["labels"].(map[string]any)["app.kubernetes.io/managed-by"] != "matii-operator" {
		t.Fatal("missing managed-by label")
	}
	if owner := meta["ownerReferences"].([]any)[0].(map[string]any); owner["uid"] != "uid-1" {
		t.Fatal("missing owner reference")
	}
	if len(fk.tokenReqs) != 1 || fk.tokenReqs[0] != "/api/v1/namespaces/payments/serviceaccounts/reader/token" {
		t.Fatalf("token requests: %v", fk.tokenReqs)
	}
	if len(fk.restarts) != 1 || fk.statuses[0]["ready"] != true {
		t.Fatalf("restarts %v status %v", fk.restarts, fk.statuses)
	}

	// Unchanged values: no write, no restart.
	op.nextRun = map[string]time.Time{}
	if err := op.Reconcile(context.Background(), mustMatiiSecret(t, fk.items[0])); err != nil {
		t.Fatal(err)
	}
	if fk.applies != 1 || len(fk.restarts) != 1 {
		t.Fatalf("rewrote unchanged secret: applies=%d restarts=%d", fk.applies, len(fk.restarts))
	}

	// Changed value: rewrite and restart.
	values["API_KEY"] = "k2"
	if err := op.Reconcile(context.Background(), mustMatiiSecret(t, fk.items[0])); err != nil {
		t.Fatal(err)
	}
	if fk.applies != 2 || len(fk.restarts) != 2 {
		t.Fatalf("change not applied: applies=%d restarts=%d", fk.applies, len(fk.restarts))
	}
}

func TestRefusesToOverwriteUnmanagedSecret(t *testing.T) {
	values := map[string]string{"K": "v"}
	op, fk := setup(t, &values)
	fk.secrets["tls"] = map[string]any{"metadata": map[string]any{"labels": map[string]string{}}}
	err := op.Reconcile(context.Background(), mustMatiiSecret(t, resource("tls")))
	if err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if fk.applies != 0 || fk.statuses[0]["ready"] != false {
		t.Fatal("unmanaged secret touched or status not reported")
	}
}

func TestInvalidKeysAndSpecsAreReported(t *testing.T) {
	values := map[string]string{"bad key!": "v"}
	op, fk := setup(t, &values)
	if err := op.Reconcile(context.Background(), mustMatiiSecret(t, resource("s"))); err == nil {
		t.Fatal("invalid key accepted")
	}
	broken := resource("s")
	delete(broken["spec"].(map[string]any), "serviceAccountId")
	if err := op.Reconcile(context.Background(), mustMatiiSecret(t, broken)); err == nil {
		t.Fatal("invalid spec accepted")
	}
	if fk.applies != 0 {
		t.Fatal("secret written despite errors")
	}
}

func TestHashIsStableAndUnambiguous(t *testing.T) {
	if Hash(map[string]string{"a": "1", "b": "2"}) != Hash(map[string]string{"b": "2", "a": "1"}) {
		t.Fatal("hash depends on order")
	}
	if Hash(map[string]string{"a": "b=c"}) == Hash(map[string]string{"a=b": "c"}) {
		t.Fatal("ambiguous hash")
	}
}

func mustMatiiSecret(t *testing.T, raw map[string]any) *MatiiSecret {
	b, _ := json.Marshal(raw)
	var ms MatiiSecret
	if err := json.Unmarshal(b, &ms); err != nil {
		t.Fatal(err)
	}
	return &ms
}
