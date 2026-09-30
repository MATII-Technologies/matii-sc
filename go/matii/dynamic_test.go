package matii

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLeaseDynamic(t *testing.T) {
	v := loadVectors(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service/secrets/tokens/":
			_, _ = w.Write([]byte(`{"wrapped_key_share":"` + v.WrappedKeyShare + `","apps":[{"id":"a1","name":"Billing","encryption":"SSE","environment_keys":[{"environment":{"id":"e1","name":"production"}}]}]}`))
		case "/service/v1/dynamic-secrets/lease/":
			if r.Method != http.MethodPost || r.URL.Query().Get("app_id") != "a1" || r.URL.Query().Get("env") != "production" ||
				r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("request %s %s %v", r.Method, r.URL, r.Header)
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["name"] != "deploy" || body["path"] != "/ops" || body["ttlSeconds"] != float64(1800) {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"bad body"}`))
				return
			}
			_, _ = w.Write([]byte(`{"leaseId":"l1","expiresAt":"2030-01-01T00:00:00Z","credentials":{"AWS_ACCESS_KEY_ID":"ASIA","AWS_SECRET_ACCESS_KEY":"s","AWS_SESSION_TOKEN":"t"}}`))
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
	lease, err := client.LeaseDynamic(context.Background(), Query{AppName: "billing", Env: "production", Path: "/ops"}, "deploy", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if lease.ID != "l1" || lease.Credentials["AWS_SESSION_TOKEN"] != "t" || lease.ExpiresAt.Year() != 2030 {
		t.Fatalf("%#v", lease.Credentials)
	}
	if strings.Contains(lease.String(), "ASIA") {
		t.Fatal("String() leaks credentials")
	}
	if _, err := client.LeaseDynamic(context.Background(), Query{AppName: "billing", Env: "production"}, "deploy", time.Minute); err == nil {
		t.Fatal("server error not returned")
	}
}
