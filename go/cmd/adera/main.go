// Command adera is the command-line client of the Matii Secret Service.
//
//	adera auth login | status | logout      sign in (browser, or --token)
//	adera init                              link this directory to an app and environment
//	adera secrets list|get|create|update|delete|import|export
//	adera run -- command                    run a program with secrets in its environment
//	adera shell                             open a shell with secrets in its environment
//	adera dynamic list|lease|leases         dynamic (short-lived) credentials
//	adera users whoami|switch|logout        accounts
//	adera console | docs | update | completion | version
//
// The app and environment come from --app/--app-id and --env, else
// ADERA_APP/ADERA_APP_ID and ADERA_ENV, else .adera.json (adera init).
//
// Authentication (environment variables, else the account from adera auth login):
//
//	ADERA_HOST                  console URL, e.g. https://secrets.example.com
//	ADERA_TOKEN / ADERA_TOKEN_FILE        a service account token (pss_service:v2:...)
//	or workload identity (no stored token):
//	ADERA_SERVICE_ACCOUNT_ID    service account with an OIDC identity attached
//	ADERA_OIDC_TOKEN_FILE       e.g. a Kubernetes projected token path, or
//	ADERA_OIDC_PROVIDER=github-actions with ADERA_OIDC_AUDIENCE (default matii-secret-service)
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

var version = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// usageError is reported with exit code 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var err error
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "adera", version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "auth":
		return authCommand(args[1:], stdout, stderr)
	case "run":
		return runCommand(args[1:], stderr)
	case "shell":
		return shellCommand(args[1:], stderr)
	case "init":
		err = initCommand(ctx, args[1:], stdout, stderr)
	case "secrets":
		if len(args) < 2 {
			usage(stderr)
			return 2
		}
		err = secretsCommand(ctx, args[1], args[2:], stdout, stderr)
	case "dynamic", "dynamic-secrets":
		if len(args) < 2 {
			usage(stderr)
			return 2
		}
		err = dynamicCommand(ctx, args[1], args[2:], stdout, stderr)
	case "users":
		if len(args) < 2 {
			usage(stderr)
			return 2
		}
		if args[1] == "logout" {
			fs := flag.NewFlagSet("logout", flag.ContinueOnError)
			fs.SetOutput(stderr)
			purge := fs.Bool("purge", false, "sign out of every account")
			if fs.Parse(args[2:]) != nil {
				return 2
			}
			return logout(*purge, stdout, stderr)
		}
		err = usersCommand(ctx, args[1], args[2:], stdout, stderr)
	case "console":
		err = consoleCommand(ctx, args[1:], stdout)
	case "docs":
		err = docsCommand(stdout)
	case "update":
		err = updateCommand(ctx, stdout, stderr)
	case "completion":
		err = completionCommand(args[1:], stdout)
	default:
		if code, ok := dispatchPlugin(args, stdout, stderr); ok {
			return code
		}
		fmt.Fprintf(stderr, "adera: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	return exitCode(err, stderr)
}

func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "adera:", err)
	var apiErr *matii.APIError
	var uErr usageError
	switch {
	case errors.As(err, &uErr):
		return 2
	case errors.As(err, &apiErr) && (apiErr.Status == 401 || apiErr.Status == 403):
		return 3
	}
	return 1
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: adera COMMAND [flags]

Account:
  auth login   [--host URL] [--no-browser] [--token]   sign in (browser, or paste a token)
  auth status | logout
  users whoami | switch [ACCOUNT] | logout [--purge]

Project:
  init         [--app APP | --app-id ID] [--env ENV] [--monorepo]   writes .adera.json

Secrets (target flags: --app APP | --app-id ID, --env ENV, --path PATH, --tags a,b):
  secrets list    [--show]
  secrets get     KEY [--format value|json]
  secrets create  [KEY] [--random hex|alphanumeric|base64|base64url|key128|key256] [--length N]
                  [--comment TEXT] [--type secret|sealed|config] [--override]   (value from stdin or a prompt)
  secrets update  KEY [--random TYPE] [--length N] [--updated-path PATH] [--comment TEXT]
                  [--type TYPE] [--override] [--toggle-override]
  secrets delete  KEY...
  secrets import  FILE|-
  secrets export  [KEY...] [--format dotenv|json|csv|yaml|xml|toml|hcl|ini|java_properties|kv|shell|github]

Programs:
  run    [--dynamic NAME]... [--ttl 1h] -- command [args...]    or: run "command string"
  shell  [--shell bash|zsh|fish|...]

Dynamic secrets:
  dynamic list
  dynamic lease  NAME [--ttl 1h] [--format dotenv|json|shell]
  dynamic leases NAME

Packages (when matii-pkg is installed; see adera pkg --help):
  pkg <command>           any Matii Package Platform command (adera pkg init, ...)
  add | install | publish | search | info | audit | login | whoami | ...   forwarded to matii-pkg

Other:
  console [--app-only]    open the console (at this project's environment)
  docs                    open the user guides
  update                  install the latest adera from your console
  completion bash|zsh|fish
  version

The app and environment come from flags, else ADERA_APP / ADERA_APP_ID / ADERA_ENV, else .adera.json.
Sign in with adera auth login, or set ADERA_HOST and ADERA_TOKEN (or workload identity; see docs).`)
}

// --- flags and target ---------------------------------------------------------------

type target struct {
	app, appID, env, path, tags string
}

func addTarget(fs *flag.FlagSet) *target {
	t := &target{}
	fs.StringVar(&t.app, "app", "", "app name")
	fs.StringVar(&t.appID, "app-id", "", "app id")
	fs.StringVar(&t.env, "env", "", "environment name (a unique prefix is enough)")
	fs.StringVar(&t.path, "path", "", "folder path, e.g. /backend")
	fs.StringVar(&t.tags, "tags", "", "only secrets with one of these tags (comma-separated)")
	return t
}

// complete fills the app and environment from ADERA_* variables and .adera.json.
func (t *target) complete() error {
	if t.app == "" && t.appID == "" {
		t.app, t.appID = os.Getenv("ADERA_APP"), os.Getenv("ADERA_APP_ID")
	}
	if t.env == "" {
		t.env = os.Getenv("ADERA_ENV")
	}
	if (t.app == "" && t.appID == "") || t.env == "" {
		if p, _, err := findProject(); err == nil {
			if t.app == "" && t.appID == "" {
				t.appID, t.app = p.AppID, p.AppName
			}
			if t.env == "" {
				t.env = p.DefaultEnv
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if (t.app == "" && t.appID == "") || t.env == "" {
		return usagef("--app (or --app-id) and --env are required (or run adera init)")
	}
	return nil
}

func (t *target) query() matii.Query {
	return matii.Query{AppID: t.appID, AppName: t.app, Env: t.env, Path: t.path}
}

func (t *target) tagList() []string {
	var out []string
	for _, tag := range strings.Split(t.tags, ",") {
		if tag = strings.TrimSpace(tag); tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// hasTag reports whether tags contains one of want (case-insensitive); an
// empty want matches everything.
func hasTag(tags, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, have := range tags {
		for _, w := range want {
			if strings.EqualFold(have, w) {
				return true
			}
		}
	}
	return false
}

// parseArgs parses flags that may be mixed with positional arguments. Anything
// after "--" is returned separately (dashed is true if "--" was present).
func parseArgs(fs *flag.FlagSet, args []string) (positional, afterDash []string, dashed bool, err error) {
	for i, a := range args {
		if a == "--" {
			args, afterDash, dashed = args[:i], args[i+1:], true
			break
		}
	}
	fs.SetOutput(io.Discard)
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, false, usageError{err.Error()}
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, afterDash, dashed, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// --- client --------------------------------------------------------------------

func httpClient(targetURL string) *http.Client {
	u, _ := url.Parse(targetURL)
	isLocal := u != nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	insecure := os.Getenv("ADERA_TLS_SKIP_VERIFY") == "true" ||
		os.Getenv("ADERA_TLS_SKIP_VERIFY") == "1" ||
		os.Getenv("ADERA_INSECURE_TLS") == "true" ||
		os.Getenv("ADERA_INSECURE_TLS") == "1" ||
		(isLocal && os.Getenv("ADERA_STRICT_TLS") != "true")
	if insecure {
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return nil
}

func newClient() (*matii.Client, error) {
	host := os.Getenv("ADERA_HOST")
	apiBase := os.Getenv("ADERA_API_BASE")
	if host == "" && apiBase == "" {
		// Fall back to `adera auth login` credentials.
		if c, err := loadCredentials(); err == nil {
			host = c.Host
		} else {
			return nil, errors.New("sign in with adera auth login, or set ADERA_HOST (e.g. https://secrets.example.com)")
		}
	}
	if apiBase == "" {
		apiBase = strings.TrimRight(host, "/") + "/service"
	}
	tokens, err := tokenSource(apiBase)
	if err != nil {
		return nil, err
	}
	return matii.New(matii.Config{APIBase: apiBase, Tokens: tokens, HTTPClient: httpClient(apiBase)})
}

// consoleHost is the console URL for links (ADERA_HOST, else the signed-in account).
func consoleHost() (string, error) {
	if h := os.Getenv("ADERA_HOST"); h != "" {
		return strings.TrimRight(h, "/"), nil
	}
	if c, err := loadCredentials(); err == nil {
		return c.Host, nil
	}
	return "", errors.New("sign in with adera auth login, or set ADERA_HOST")
}

func tokenSource(apiBase string) (matii.TokenSource, error) {
	if raw := os.Getenv("ADERA_TOKEN"); raw != "" {
		return matii.StaticToken(raw)
	}
	if path := os.Getenv("ADERA_TOKEN_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return matii.StaticToken(string(b))
	}
	saID := os.Getenv("ADERA_SERVICE_ACCOUNT_ID")
	if saID == "" {
		if c, err := loadCredentials(); err == nil && strings.TrimRight(c.Host, "/")+"/service" == strings.TrimRight(apiBase, "/") {
			return matii.StaticToken(c.Token)
		}
		return nil, errors.New("sign in with adera auth login, or set ADERA_TOKEN, ADERA_TOKEN_FILE, or ADERA_SERVICE_ACCOUNT_ID for workload identity")
	}
	source := &matii.OIDCTokenSource{APIBase: apiBase, ServiceAccountID: saID}
	switch {
	case os.Getenv("ADERA_OIDC_TOKEN_FILE") != "":
		source.JWT = matii.FileJWT(os.Getenv("ADERA_OIDC_TOKEN_FILE"))
	case os.Getenv("ADERA_OIDC_PROVIDER") == "github-actions":
		audience := os.Getenv("ADERA_OIDC_AUDIENCE")
		if audience == "" {
			audience = "matii-secret-service"
		}
		source.JWT = matii.GitHubActionsJWT(audience, nil)
	default:
		return nil, errors.New("workload identity needs ADERA_OIDC_TOKEN_FILE or ADERA_OIDC_PROVIDER=github-actions")
	}
	return source, nil
}

// --- terminal input ------------------------------------------------------------------

var stdin = bufio.NewReader(os.Stdin)

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// prompt reads one line from stdin after printing label to w.
func prompt(w io.Writer, label string) (string, error) {
	fmt.Fprint(w, label)
	line, err := stdin.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptSecret is prompt without echo (where the terminal supports it).
func promptSecret(w io.Writer, label string) (string, error) {
	if runtime.GOOS != "windows" && isTerminal(os.Stdin) {
		if setEcho(false) == nil {
			defer func() {
				_ = setEcho(true)
				fmt.Fprintln(w)
			}()
		}
	}
	return prompt(w, label)
}

func setEcho(on bool) error {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// readStdin reads piped input, dropping one trailing newline.
func readStdin() (string, error) {
	b, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.TrimSuffix(s, "\r"), nil
}

// choose asks the user to pick one of options by number or exact name.
func choose(w io.Writer, title string, options []string) (int, error) {
	if !isTerminal(os.Stdin) {
		return 0, usagef("%s: pass it as a flag (no terminal to ask on)", strings.ToLower(title))
	}
	fmt.Fprintln(w, title+":")
	for i, o := range options {
		fmt.Fprintf(w, "  %d) %s\n", i+1, o)
	}
	for {
		answer, err := prompt(w, "Choose 1-"+fmt.Sprint(len(options))+": ")
		if err != nil {
			return 0, err
		}
		answer = strings.TrimSpace(answer)
		for i, o := range options {
			if fmt.Sprint(i+1) == answer || strings.EqualFold(o, answer) {
				return i, nil
			}
		}
	}
}

func openBrowserOrPrint(u string, stdout io.Writer) {
	if openBrowser(u) != nil {
		fmt.Fprintln(stdout, "Open:", u)
		return
	}
	fmt.Fprintln(stdout, "Opened", u)
}
