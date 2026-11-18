package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

const origin = "https://secrets.example.com"

// Shared with the console's web page test (frontend/tests/matii/webauth.test.ts).
func TestVerificationCodeVector(t *testing.T) {
	got := verificationCode(strings.Repeat("ab", 32))
	if got != "271A-413B" {
		t.Fatalf("verificationCode = %s", got)
	}
}

func testKeyPair(t *testing.T) matii.KeyPair {
	kp, err := matii.KXSeedKeyPair(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func post(t *testing.T, h http.Handler, from string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("Origin", from)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCallbackAcceptsOneEncryptedTokenFromTheConsole(t *testing.T) {
	kp := testKeyPair(t)
	results := make(chan *loginResult, 1)
	h := callbackHandler(origin, kp, results)
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	encToken, _ := matii.EncryptAsymmetric(token, kp.Public)
	encEmail, _ := matii.EncryptAsymmetric("dev@acme.test", kp.Public)

	// Preflight: CORS and Private Network Access.
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Private-Network") != "true" ||
		rec.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Fatalf("preflight: %d %v", rec.Code, rec.Header())
	}

	if rec := post(t, h, "https://evil.example", map[string]string{"pss": encToken}); rec.Code != http.StatusForbidden {
		t.Fatalf("other origin: %d", rec.Code)
	}
	plain, _ := matii.EncryptAsymmetric("pss_service:v2:x", kp.Public)
	if rec := post(t, h, origin, map[string]string{"pss": plain}); rec.Code != http.StatusBadRequest {
		t.Fatalf("service token accepted: %d", rec.Code)
	}
	other, _ := matii.KXSeedKeyPair(bytes.Repeat([]byte{8}, 32))
	wrongKey, _ := matii.EncryptAsymmetric(token, other.Public)
	if rec := post(t, h, origin, map[string]string{"pss": wrongKey}); rec.Code != http.StatusBadRequest {
		t.Fatalf("token for another key accepted: %d", rec.Code)
	}

	if rec := post(t, h, origin, map[string]string{"pss": encToken, "email": encEmail}); rec.Code != http.StatusOK {
		t.Fatalf("valid: %d %s", rec.Code, rec.Body)
	}
	r := <-results
	if r.token != token || r.email != "dev@acme.test" {
		t.Fatalf("result %+v", r)
	}
	if rec := post(t, h, origin, map[string]string{"pss": encToken}); rec.Code != http.StatusConflict {
		t.Fatalf("second post: %d", rec.Code)
	}
}

func TestCredentialsRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adera", "credentials.json")
	t.Setenv("ADERA_CREDENTIALS_FILE", path)
	if _, err := storeAccount(credentials{ID: "a1", Host: origin, Token: "t", Email: "e"}); err != nil {
		t.Fatal(err)
	}
	c, err := loadCredentials()
	if err != nil || c.Host != origin || c.Token != "t" {
		t.Fatalf("load: %v %+v", err, c)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", info.Mode().Perm())
		}
		os.Chmod(path, 0o644)
		if _, err := loadCredentials(); err == nil {
			t.Fatal("world-readable credentials accepted")
		}
	}
}

func TestCredentialStoreAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("ADERA_CREDENTIALS_FILE", path)
	// A file written by an older version: one account at the top level.
	if err := os.WriteFile(path, []byte(`{"host":"`+origin+`","token":"old","email":"a@x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := loadCredentials(); err != nil || c.Token != "old" {
		t.Fatalf("legacy file: %v %+v", err, c)
	}
	if _, err := storeAccount(credentials{ID: "b", Host: origin, Token: "new", Email: "b@x"}); err != nil {
		t.Fatal(err)
	}
	// Signing in again as the same person replaces that account.
	if _, err := storeAccount(credentials{ID: "b2", Host: origin, Token: "newer", Email: "b@x"}); err != nil {
		t.Fatal(err)
	}
	store, err := loadStore()
	if err != nil || len(store.Accounts) != 2 || store.current().Token != "newer" {
		t.Fatalf("store: %v %+v", err, store)
	}
	var out, errOut strings.Builder
	if code := run([]string{"users", "switch", "a@x"}, &out, &errOut); code != 0 {
		t.Fatalf("switch: %d %s", code, errOut.String())
	}
	if c, _ := loadCredentials(); c.Token != "old" {
		t.Fatalf("switch kept %q", c.Token)
	}
	if code := run([]string{"users", "logout"}, &out, &errOut); code != 0 {
		t.Fatal(errOut.String())
	}
	if c, _ := loadCredentials(); c == nil || c.Token != "newer" {
		t.Fatalf("after logout: %+v", c)
	}
	if code := run([]string{"users", "logout", "--purge"}, &out, &errOut); code != 0 {
		t.Fatal(errOut.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("purge kept the file")
	}
}

func TestLoginArguments(t *testing.T) {
	if _, err := consoleOrigin("http://secrets.example.com"); err == nil {
		t.Fatal("plain http accepted")
	}
	if o, err := consoleOrigin("https://secrets.example.com/some/path/"); err != nil || o != origin {
		t.Fatalf("origin %q %v", o, err)
	}
	if got := sanitizeTokenName("cli-on my laptop"); got != "cli_on_my_laptop" {
		t.Fatalf("sanitize %q", got)
	}
}

func TestPersonalAccessTokensParse(t *testing.T) {
	tok := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	parsed, err := matii.ParseToken(tok)
	if err != nil || parsed.Kind() != "User" {
		t.Fatalf("%v %v", parsed, err)
	}
	if _, err := matii.ParseToken(strings.Replace(tok, "pss_user", "pss_service", 1)); err == nil {
		t.Fatal("pss_service:v1 accepted")
	}
}

func TestWebauthURLIsBase64OfTheRequest(t *testing.T) {
	u := webauthURL(origin, 4242, strings.Repeat("ab", 32), "adera_cli@laptop")
	want := origin + "/webauth/" + url.PathEscape(base64.StdEncoding.EncodeToString([]byte("4242-"+strings.Repeat("ab", 32)+"-adera_cli@laptop")))
	if u != want {
		t.Fatalf("%s", u)
	}
}
