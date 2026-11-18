package main

// Interactive sign-in for people: `adera auth login` opens the console's web
// authentication page, which creates a personal access token for the signed-in
// member, encrypts it to a key pair generated here, and posts it to a listener
// on 127.0.0.1. The token is stored in the user's config directory (0600).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

const loginTimeout = 5 * time.Minute

// credentials is one signed-in account.
type credentials struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Token   string `json:"token"`
	Email   string `json:"email,omitempty"`
	Created string `json:"created,omitempty"`
}

func (c *credentials) label() string {
	who := c.Email
	if who == "" {
		who = "token " + c.ID
	}
	return who + " on " + c.Host
}

// credentialStore is what `adera auth login` stores: every signed-in account
// and the one in use. Files written by older versions hold one account's
// fields at the top level and are read as a single account.
type credentialStore struct {
	Default  string        `json:"default"`
	Accounts []credentials `json:"accounts"`
}

func (s *credentialStore) current() *credentials {
	for i := range s.Accounts {
		if s.Accounts[i].ID == s.Default {
			return &s.Accounts[i]
		}
	}
	if len(s.Accounts) > 0 {
		return &s.Accounts[0]
	}
	return nil
}

// add stores c (replacing the same person on the same host) and makes it current.
func (s *credentialStore) add(c credentials) {
	kept := s.Accounts[:0]
	for _, a := range s.Accounts {
		if !(a.Host == c.Host && a.Email != "" && a.Email == c.Email) {
			kept = append(kept, a)
		}
	}
	s.Accounts = append(kept, c)
	s.Default = c.ID
}

func (s *credentialStore) remove(id string) {
	kept := s.Accounts[:0]
	for _, a := range s.Accounts {
		if a.ID != id {
			kept = append(kept, a)
		}
	}
	s.Accounts = kept
	if s.Default == id {
		s.Default = ""
		if len(kept) > 0 {
			s.Default = kept[0].ID
		}
	}
}

func newAccountID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func credentialsPath() (string, error) {
	if p := os.Getenv("ADERA_CREDENTIALS_FILE"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "adera", "credentials.json"), nil
}

// loadCredentials returns the account in use.
func loadCredentials() (*credentials, error) {
	store, err := loadStore()
	if err != nil {
		return nil, err
	}
	if c := store.current(); c != nil {
		return c, nil
	}
	return nil, os.ErrNotExist
}

func loadStore() (*credentialStore, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users; run: chmod 600 %s", path, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	invalid := fmt.Errorf("%s is not valid; run adera auth login again", path)
	var store credentialStore
	if err := json.Unmarshal(b, &store); err != nil {
		return nil, invalid
	}
	if store.Accounts == nil {
		var single credentials
		if json.Unmarshal(b, &single) != nil || single.Host == "" || single.Token == "" {
			return nil, invalid
		}
		single.ID = "default"
		store = credentialStore{Default: single.ID, Accounts: []credentials{single}}
	}
	for _, a := range store.Accounts {
		if a.Host == "" || a.Token == "" || a.ID == "" {
			return nil, invalid
		}
	}
	return &store, nil
}

func saveStore(c *credentialStore) (string, error) {
	path, err := credentialsPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	return path, os.Rename(tmp, path)
}

// verificationCode is shown in the terminal and on the web page, so the user
// can check the page is answering this CLI and not a link someone sent them.
func verificationCode(publicKeyHex string) string {
	sum := sha256.Sum256([]byte(publicKeyHex))
	code := strings.ToUpper(hex.EncodeToString(sum[:4]))
	return code[:4] + "-" + code[4:]
}

func authCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		args = append([]string{"login"}, args...) // `adera auth` signs in
	}
	switch args[0] {
	case "login":
		return authLogin(args[1:], stdout, stderr)
	case "status":
		c, err := loadCredentials()
		if err != nil {
			fmt.Fprintln(stdout, "Not signed in (adera auth login).")
			return 3
		}
		who := c.Email
		if who == "" {
			who = "a token"
		}
		fmt.Fprintf(stdout, "Signed in to %s as %s.\n", c.Host, who)
		return 0
	case "logout":
		return logout(false, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: adera auth login|status|logout")
		return 2
	}
}

func authLogin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", os.Getenv("ADERA_HOST"), "console URL, e.g. https://secrets.example.com")
	name := fs.String("name", "", "name for the personal access token (default: adera_cli@<hostname>)")
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening a browser")
	withToken := fs.Bool("token", false, "paste a token (personal access token or service account token) instead of using the browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *host == "" && isTerminal(os.Stdin) {
		*host, _ = prompt(stderr, "Console URL (e.g. https://secrets.example.com): ")
	}
	origin, err := consoleOrigin(*host)
	if err != nil {
		fmt.Fprintln(stderr, "adera:", err)
		return 2
	}
	if *withToken {
		return tokenLogin(origin, stdout, stderr)
	}
	tokenName := *name
	if tokenName == "" {
		hn, _ := os.Hostname()
		tokenName = "adera_cli@" + hn
	}
	tokenName = sanitizeTokenName(tokenName)

	result, err := webLogin(origin, tokenName, *noBrowser, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "adera:", err)
		return 1
	}
	path, err := storeAccount(credentials{
		ID: newAccountID(), Host: origin, Token: result.token, Email: result.email, Created: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		fmt.Fprintln(stderr, "adera: could not store the token:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Signed in to %s as %s. Token stored in %s.\n", origin, result.email, path)
	return 0
}

// storeAccount adds an account to the credentials file and makes it current.
func storeAccount(c credentials) (string, error) {
	store, err := loadStore()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		store = &credentialStore{}
	}
	store.add(c)
	return saveStore(store)
}

// tokenLogin stores a pasted token after checking it against the server.
func tokenLogin(origin string, stdout, stderr io.Writer) int {
	var raw string
	var err error
	if isTerminal(os.Stdin) {
		raw, err = promptSecret(stderr, "Token: ")
	} else {
		raw, err = readStdin()
	}
	if err != nil {
		fmt.Fprintln(stderr, "adera:", err)
		return 1
	}
	raw = strings.TrimSpace(raw)
	tokens, err := matii.StaticToken(raw)
	if err != nil {
		fmt.Fprintln(stderr, "adera:", err)
		return 2
	}
	client, err := matii.New(matii.Config{Host: origin, Tokens: tokens, HTTPClient: httpClient(origin)})
	if err != nil {
		fmt.Fprintln(stderr, "adera:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	who, err := client.Whoami(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "adera: the token was not accepted:", err)
		return 3
	}
	path, err := storeAccount(credentials{ID: newAccountID(), Host: origin, Token: raw, Created: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		fmt.Fprintln(stderr, "adera: could not store the token:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Signed in to %s (%s token, organisation %s). Token stored in %s.\n", origin, who.Kind, who.OrganisationName, path)
	return 0
}

// logout forgets the current account (or every account with purge).
func logout(purge bool, stdout, stderr io.Writer) int {
	store, err := loadStore()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stdout, "Not signed in.")
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "adera:", err)
		return 1
	}
	path, _ := credentialsPath()
	if purge || len(store.Accounts) <= 1 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "adera:", err)
			return 1
		}
		fmt.Fprintln(stdout, "Signed out of every account. The tokens still exist on the server: delete them in the console under Account → Personal access tokens.")
		return 0
	}
	current := store.current()
	store.remove(current.ID)
	if _, err := saveStore(store); err != nil {
		fmt.Fprintln(stderr, "adera:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Signed out of %s; now using %s. The token still exists on the server: delete it in the console under Account → Personal access tokens.\n", current.label(), store.current().label())
	return 0
}

func consoleOrigin(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("give --host (or set ADERA_HOST), e.g. --host https://secrets.example.com")
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", errors.New("--host must be a URL such as https://secrets.example.com")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return "", errors.New("--host must use https (plain http only for localhost)")
	}
	return u.Scheme + "://" + u.Host, nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// The web page splits the request code on "-", so the name must not contain one.
func sanitizeTokenName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '@':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

type loginResult struct{ token, email string }

func webLogin(origin, tokenName string, noBrowser bool, stdout io.Writer) (*loginResult, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	kp, err := matii.KXSeedKeyPair(seed[:])
	if err != nil {
		return nil, err
	}
	pubHex := hex.EncodeToString(kp.Public[:])

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	results := make(chan *loginResult, 1)
	srv := &http.Server{Handler: callbackHandler(origin, kp, results), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln) //nolint:errcheck // closed below
	defer srv.Close()

	loginURL := webauthURL(origin, port, pubHex, tokenName)
	code := verificationCode(pubHex)
	fmt.Fprintf(stdout, "Verification code: %s\nConfirm this code in the browser.\n", code)
	if noBrowser || openBrowser(loginURL) != nil {
		fmt.Fprintf(stdout, "Open this URL to sign in:\n  %s\n", loginURL)
	} else {
		fmt.Fprintf(stdout, "Opened %s in your browser. If nothing appeared, open:\n  %s\n", origin, loginURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	select {
	case r := <-results:
		return r, nil
	case <-ctx.Done():
		return nil, errors.New("timed out waiting for the browser (5 minutes)")
	}
}

// callbackHandler accepts one POST {"email": ph:v1..., "pss": ph:v1...} from the console origin.
func callbackHandler(origin string, kp matii.KeyPair, results chan<- *loginResult) http.Handler {
	var used atomic.Bool
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != origin {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			// Chrome's Private Network Access preflight for a public page calling 127.0.0.1.
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Email string `json:"email"`
			PSS   string `json:"pss"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		token, err := matii.DecryptAsymmetric(body.PSS, kp)
		if err != nil {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}
		if _, err := matii.ParseToken(token); err != nil || !strings.HasPrefix(token, "pss_user:") {
			http.Error(w, "not a personal access token", http.StatusBadRequest)
			return
		}
		email, _ := matii.DecryptAsymmetric(body.Email, kp)
		if !used.CompareAndSwap(false, true) {
			http.Error(w, "already signed in", http.StatusConflict)
			return
		}
		results <- &loginResult{token: token, email: email}
		w.WriteHeader(http.StatusOK)
	})
}

// webauthURL: the console decodes the path segment as standard base64 of "port-publickey-name".
func webauthURL(origin string, port int, pubHex, tokenName string) string {
	code := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d-%s-%s", port, pubHex, tokenName)))
	return origin + "/webauth/" + url.PathEscape(code)
}

func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}
