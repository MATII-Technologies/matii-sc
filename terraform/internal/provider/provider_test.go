package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type vectors struct {
	Token           string `json:"token"`
	WrappedKeyShare string `json:"wrapped_key_share"`
}

// fakeAPI is an in-memory Secret Service with one server-side encrypted app.
type fakeAPI struct {
	mu      sync.Mutex
	secrets map[string]map[string]string // id -> {key, value, path, comment}
	next    int
	calls   []string
}

func (f *fakeAPI) handler(v vectors) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/service/secrets/tokens/":
			fmt.Fprintf(w, `{"wrapped_key_share":%q,"apps":[{"id":"a1","name":"Payments","encryption":"SSE","environment_keys":[{"environment":{"id":"e1","name":"production"}}]}]}`, v.WrappedKeyShare)
		case r.URL.Path == "/service/v1/secrets/" && r.Method == http.MethodGet:
			out := []map[string]string{}
			for id, s := range f.secrets {
				if k := r.URL.Query().Get("key"); k != "" && k != s["key"] {
					continue
				}
				if p := r.URL.Query().Get("path"); p != "" && p != s["path"] {
					continue
				}
				out = append(out, map[string]string{"id": id, "key": s["key"], "value": s["value"], "path": s["path"], "comment": s["comment"]})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.URL.Path == "/service/v1/secrets/" && r.Method == http.MethodPost:
			var body struct{ Secrets []map[string]string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, s := range body.Secrets {
				f.next++
				f.secrets[fmt.Sprintf("s%d", f.next)] = map[string]string{"key": strings.ToUpper(s["key"]), "value": s["value"], "path": s["path"], "comment": s["comment"]}
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/service/v1/secrets/" && r.Method == http.MethodPut:
			var body struct{ Secrets []map[string]string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, s := range body.Secrets {
				f.secrets[s["id"]]["value"], f.secrets[s["id"]]["comment"] = s["value"], s["comment"]
			}
		case r.URL.Path == "/service/v1/secrets/" && r.Method == http.MethodDelete:
			var body struct{ Secrets []string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, id := range body.Secrets {
				delete(f.secrets, id)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestAccSecretLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" && os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 (and TF_ACC_TERRAFORM_PATH to a terraform or tofu binary)")
	}
	raw, err := os.ReadFile("../../../go/matii/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	_ = json.Unmarshal(raw, &v)
	api := &fakeAPI{secrets: map[string]map[string]string{"s0": {"key": "EXISTING", "value": "e", "path": "/", "comment": ""}}}
	srv := httptest.NewServer(api.handler(v))
	defer srv.Close()

	config := func(value string) string {
		return fmt.Sprintf(`
provider "matii" {
  host  = %q
  token = %q
}
resource "matii_secret" "db" {
  app     = "Payments"
  env     = "production"
  path    = "/backend"
  key     = "DB_URL"
  value   = %q
  comment = "managed by terraform"
}
data "matii_secrets" "prod" {
  app        = "Payments"
  env        = "production"
  depends_on = [matii_secret.db]
}
`, srv.URL, v.Token, value)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"matii": providerserver.NewProtocol6WithError(New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: config("postgres://one"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("matii_secret.db", "key", "DB_URL"),
					resource.TestCheckResourceAttrSet("matii_secret.db", "id"),
					resource.TestCheckResourceAttr("data.matii_secrets.prod", "values.EXISTING", "e"),
					resource.TestCheckResourceAttr("data.matii_secrets.prod", "values.DB_URL", "postgres://one"),
				),
			},
			{
				Config: config("postgres://two"),
				Check: func(*terraform.State) error {
					api.mu.Lock()
					defer api.mu.Unlock()
					for _, s := range api.secrets {
						if s["key"] == "DB_URL" && s["value"] == "postgres://two" && s["path"] == "/backend" {
							return nil
						}
					}
					return fmt.Errorf("value not updated in place: %v", api.secrets)
				},
			},
			{
				ResourceName:            "matii_secret.db",
				ImportState:             true,
				ImportStateId:           "Payments/production/backend/DB_URL",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"id"},
			},
		},
		CheckDestroy: func(*terraform.State) error {
			api.mu.Lock()
			defer api.mu.Unlock()
			for _, s := range api.secrets {
				if s["key"] == "DB_URL" {
					return fmt.Errorf("secret not deleted")
				}
			}
			return nil
		},
	})
}

func TestAccLowerCaseKeyIsRejected(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1")
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"matii": providerserver.NewProtocol6WithError(New("test")()),
		},
		Steps: []resource.TestStep{{
			Config: `
provider "matii" {
  host  = "http://127.0.0.1:1"
  token = "pss_service:v2:x"
}
resource "matii_secret" "x" {
  app   = "A"
  env   = "e"
  key   = "lower"
  value = "v"
}`,
			ExpectError: regexp.MustCompile(`write "LOWER"`),
		}},
	})
}
