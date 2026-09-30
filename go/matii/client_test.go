package matii

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCTokenSourceExchangesAndCaches(t *testing.T) {
	v := loadVectors(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/identities/external/v1/oidc/auth/" {
			t.Errorf("path %s", r.URL.Path)
		}
		var body map[string]map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["oidc"]["token"] != "workload-jwt" || body["account"]["id"] != "sa-1" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"no"}`))
			return
		}
		_, _ = w.Write([]byte(`{"authentication":{"token":"` + v.Token + `","TTL":600}}`))
	}))
	defer srv.Close()
	src := &OIDCTokenSource{APIBase: srv.URL, ServiceAccountID: "sa-1",
		JWT: func(context.Context) (string, error) { return "workload-jwt", nil }}
	for i := 0; i < 3; i++ {
		tok, err := src.Token(context.Background())
		if err != nil || tok.Kind() != "ServiceAccount" {
			t.Fatalf("token: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected one exchange, got %d", calls)
	}
	bad := &OIDCTokenSource{APIBase: srv.URL, ServiceAccountID: "sa-2",
		JWT: func(context.Context) (string, error) { return "workload-jwt", nil }}
	var apiErr *APIError
	if _, err := bad.Token(context.Background()); !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestNewRejectsPlainHTTPExceptLocalhost(t *testing.T) {
	v := loadVectors(t)
	tokens, _ := StaticToken(v.Token)
	if _, err := New(Config{Host: "http://secrets.example.com", Tokens: tokens}); err == nil {
		t.Fatal("accepted plain http")
	}
	if _, err := New(Config{Host: "http://localhost:8000", Tokens: tokens}); err != nil {
		t.Fatal(err)
	}
}

func TestCachedClientServesStaleOnOutage(t *testing.T) {
	v := loadVectors(t)
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		switch r.URL.Path {
		case "/service/secrets/tokens/":
			_, _ = w.Write([]byte(`{"wrapped_key_share":"` + v.WrappedKeyShare + `","apps":[{"id":"a1","name":"Billing","encryption":"SSE","environment_keys":[{"environment":{"id":"e1","name":"production"}}]}]}`))
		case "/service/v1/secrets/":
			_, _ = w.Write([]byte(`[{"key":"K","value":"v1","path":"/"},{"key":"HIDDEN","value":null,"path":"/","valueRedacted":true}]`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	tokens, _ := StaticToken(v.Token)
	client, err := New(Config{Host: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Tokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	cached := &CachedClient{Client: client, TTL: time.Nanosecond, MaxStale: time.Minute}
	q := Query{AppName: "billing", Env: "Production"}
	if value, ok, err := cached.Get(context.Background(), q, "K"); err != nil || !ok || value != "v1" {
		t.Fatalf("get: %v %v %q", err, ok, value)
	}
	if _, ok, _ := cached.Get(context.Background(), q, "HIDDEN"); ok {
		t.Fatal("redacted value returned")
	}
	fail.Store(true)
	time.Sleep(time.Millisecond)
	if value, ok, err := cached.Get(context.Background(), q, "K"); err != nil || !ok || value != "v1" {
		t.Fatal("stale value not served during outage")
	}
	cached.MaxStale = time.Nanosecond
	time.Sleep(time.Millisecond)
	if _, _, err := cached.Get(context.Background(), q, "K"); err == nil {
		t.Fatal("expected error after max staleness")
	}
}

func TestFormattersAndRedaction(t *testing.T) {
	secrets := []Secret{{Key: "B", Value: "it's \"q\"\nx"}, {Key: "A", Value: "1"}, {Key: "H", Redacted: true}}
	if got := Dotenv(secrets); got != "A=\"1\"\nB=\"it's \\\"q\\\"\\nx\"\n" {
		t.Fatalf("dotenv: %q", got)
	}
	if got := ShellExports(secrets[:1]); got != "export B='it'\"'\"'s \"q\"\nx'\n" {
		t.Fatalf("shell: %q", got)
	}
	if s := secrets[0].String(); strings.Contains(s, "it's") {
		t.Fatal("value leaked by String()")
	}
}

func TestReferenceResolution(t *testing.T) {
	secrets := []Secret{
		{Key: "A", Value: "x", Path: "/"},
		{Key: "B", Value: "${A}-${/db/C}", Path: "/"},
		{Key: "C", Value: "c", Path: "/db"},
		{Key: "LOOP", Value: "${LOOP}", Path: "/"},
		{Key: "OTHER", Value: "${staging.K}|${Other::prod.Z}|${missing}", Path: "/"},
	}
	fetch := func(_ context.Context, app, env string) ([]Secret, error) {
		if app == "" && env == "staging" {
			return []Secret{{Key: "K", Value: "k", Path: "/"}}, nil
		}
		return nil, errors.New("no access")
	}
	out, _ := resolveReferences(context.Background(), secrets, &appKeys{}, fetch)
	got := Map(out)
	if got["B"] != "x-c" || got["OTHER"] != "k|${Other::prod.Z}|${missing}" || got["LOOP"] != "${LOOP}" {
		t.Fatalf("resolved: %#v", got)
	}
}

func TestResolveEnvironmentPrefix(t *testing.T) {
	info := &bootstrapInfo{Apps: []appKeys{{ID: "a", Name: "Payments", EnvironmentKeys: []envKey{{}, {}, {}}}}}
	for i, name := range []string{"Development", "Production", "Preview"} {
		info.Apps[0].EnvironmentKeys[i].Environment.Name = name
	}
	if _, k, err := info.resolve(Query{AppName: "payments", Env: "dev"}); err != nil || k.Environment.Name != "Development" {
		t.Fatalf("prefix: %v", err)
	}
	if _, k, err := info.resolve(Query{AppName: "Payments", Env: "production"}); err != nil || k.Environment.Name != "Production" {
		t.Fatalf("exact: %v", err)
	}
	if _, _, err := info.resolve(Query{AppName: "Payments", Env: "pr"}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous prefix: %v", err)
	}
}
