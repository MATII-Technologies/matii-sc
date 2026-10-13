package main

// dynamic, users, console, docs, update and completion.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

// --- dynamic secrets -------------------------------------------------------------

func dynamicCommand(ctx context.Context, sub string, args []string, stdout, stderr io.Writer) error {
	switch sub {
	case "list":
		return dynamicList(ctx, args, stdout)
	case "lease":
		return dynamicLease(ctx, args, stdout, stderr)
	case "leases":
		return dynamicLeases(ctx, args, stdout)
	}
	return usagef("unknown command %q (list, lease, leases)", sub)
}

func dynamicList(ctx context.Context, args []string, stdout io.Writer) error {
	t, pos, err := targetArgs("list", args, nil)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("usage: matii dynamic list [--app APP] [--env ENV] [--path PATH]")
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	list, err := client.ListDynamic(ctx, t.query())
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "(no dynamic secrets)")
		return nil
	}
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPATH\tPROVIDER\tDEFAULT TTL\tMAX TTL")
	for _, d := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", d.Name, d.Path, d.Provider,
			time.Duration(d.DefaultTTLSeconds)*time.Second, time.Duration(d.MaxTTLSeconds)*time.Second)
	}
	return w.Flush()
}

func dynamicLease(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var format string
	var ttl time.Duration
	t, pos, err := targetArgs("lease", args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "format", "dotenv", "dotenv|json|shell")
		fs.DurationVar(&ttl, "ttl", 0, "lease duration, e.g. 30m (default: the definition's)")
	})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: matii dynamic lease NAME [--ttl 1h] [--format dotenv|json|shell]")
	}
	render, ok := exporters[format]
	if !ok || (format != "dotenv" && format != "json" && format != "shell") {
		return usagef("--format must be dotenv, json or shell")
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	lease, err := client.LeaseDynamic(ctx, t.query(), pos[0], ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "matii: lease %s; credentials expire at %s\n", lease.ID, lease.ExpiresAt.Local().Format(time.RFC1123))
	fmt.Fprint(stdout, render(lease.Credentials))
	return nil
}

func dynamicLeases(ctx context.Context, args []string, stdout io.Writer) error {
	t, pos, err := targetArgs("leases", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: matii dynamic leases NAME [--app APP] [--env ENV] [--path PATH]")
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	leases, err := client.DynamicLeases(ctx, t.query(), pos[0])
	if errors.Is(err, matii.ErrNotFound) {
		return fmt.Errorf("dynamic secret %s not found in %s", pos[0], normalizePath(t.path))
	}
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LEASE\tFOR\tACCESS KEY\tCREATED\tEXPIRES")
	for _, l := range leases {
		who := l.MemberEmail
		if who == "" {
			who = "service account " + l.ServiceAccountName
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", l.ID, who, l.AccessKeyID,
			l.CreatedAt.Local().Format(time.DateTime), l.ExpiresAt.Local().Format(time.DateTime))
	}
	return w.Flush()
}

// --- users ----------------------------------------------------------------------------

func usersCommand(ctx context.Context, sub string, args []string, stdout, stderr io.Writer) error {
	switch sub {
	case "whoami":
		return whoami(ctx, stdout)
	case "switch":
		return switchAccount(args, stdout, stderr)
	}
	return usagef("unknown command %q (whoami, switch, logout)", sub)
}

func whoami(ctx context.Context, stdout io.Writer) error {
	client, err := newClient()
	if err != nil {
		return err
	}
	who, err := client.Whoami(ctx)
	if err != nil {
		return err
	}
	host, _ := consoleHost()
	source := "the MATII_* environment"
	name := ""
	if os.Getenv("MATII_TOKEN") == "" && os.Getenv("MATII_TOKEN_FILE") == "" && os.Getenv("MATII_SERVICE_ACCOUNT_ID") == "" {
		if c, err := loadCredentials(); err == nil {
			source, name = "matii auth login", c.Email
		}
	}
	kind := map[string]string{"User": "person (personal access token)", "ServiceAccount": "service account"}[who.Kind]
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	if name != "" {
		fmt.Fprintf(w, "Account:\t%s\n", name)
	}
	fmt.Fprintf(w, "Type:\t%s\nAccount ID:\t%s\nOrganisation:\t%s\nConsole:\t%s\nCredentials from:\t%s\n",
		kind, who.AccountID, who.OrganisationName, host, source)
	return w.Flush()
}

func switchAccount(args []string, stdout, stderr io.Writer) error {
	store, err := loadStore()
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("not signed in (matii auth login)")
	}
	if err != nil {
		return err
	}
	if len(store.Accounts) == 0 {
		return errors.New("not signed in (matii auth login)")
	}
	var chosen *credentials
	if len(args) > 1 {
		return usagef("usage: matii users switch [EMAIL | ACCOUNT-ID]")
	}
	if len(args) == 1 {
		for i, a := range store.Accounts {
			if a.ID == args[0] || strings.EqualFold(a.Email, args[0]) {
				if chosen != nil {
					return fmt.Errorf("%q matches more than one account; use the account id", args[0])
				}
				chosen = &store.Accounts[i]
			}
		}
		if chosen == nil {
			return fmt.Errorf("no signed-in account matches %q", args[0])
		}
	} else {
		labels := make([]string, len(store.Accounts))
		for i, a := range store.Accounts {
			labels[i] = a.label() + " [" + a.ID + "]"
			if a.ID == store.current().ID {
				labels[i] += " (current)"
			}
		}
		i, err := choose(stderr, "Accounts", labels)
		if err != nil {
			return err
		}
		chosen = &store.Accounts[i]
	}
	store.Default = chosen.ID
	if _, err := saveStore(store); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Now using %s.\n", chosen.label())
	return nil
}

// --- console / docs / update ---------------------------------------------------------------

func consoleCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	t := addTarget(fs)
	if pos, _, _, err := parseArgs(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("usage: matii console [--app APP] [--env ENV]")
	}
	host, err := consoleHost()
	if err != nil {
		return err
	}
	link := host
	if t.complete() == nil {
		if client, err := newClient(); err == nil {
			who, err1 := client.Whoami(ctx)
			app, env, err2 := client.EnvironmentOf(ctx, t.query())
			if err1 == nil && err2 == nil {
				link = fmt.Sprintf("%s/%s/apps/%s/environments/%s", host, url.PathEscape(who.OrganisationName), app.ID, env.ID)
			}
		}
	}
	openBrowserOrPrint(link, stdout)
	return nil
}

func docsCommand(stdout io.Writer) error {
	host, err := consoleHost()
	if err != nil {
		return err
	}
	openBrowserOrPrint(host+"/docs", stdout)
	return nil
}

// updateCommand runs the console's install script, which verifies the
// download's checksum, and installs over the running binary.
func updateCommand(ctx context.Context, stdout, stderr io.Writer) error {
	if runtime.GOOS == "windows" {
		return errors.New("download the new matii.exe from your console's CLI page")
	}
	host, err := consoleHost()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(host, "https://") {
		return errors.New("updates are only downloaded over https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/cli/install.sh", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not download %s/cli/install.sh (HTTP %d)", host, resp.StatusCode)
	}
	script, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-s")
	cmd.Stdin = strings.NewReader(string(script))
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = append(os.Environ(), "MATII_INSTALL_DIR="+filepath.Dir(self))
	fmt.Fprintf(stdout, "Updating %s (currently %s) from %s…\n", self, version, host)
	return cmd.Run()
}

// --- completion -------------------------------------------------------------------------------

var completionWords = map[string][]string{
	"":                {"auth", "init", "secrets", "run", "shell", "dynamic", "users", "console", "docs", "update", "completion", "version", "help"},
	"auth":            {"login", "status", "logout"},
	"secrets":         {"list", "get", "create", "update", "delete", "import", "export"},
	"dynamic":         {"list", "lease", "leases"},
	"dynamic-secrets": {"list", "lease", "leases"},
	"users":           {"whoami", "switch", "logout"},
	"completion":      {"bash", "zsh", "fish"},
}

func completionCommand(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return usagef("usage: matii completion bash|zsh|fish")
	}
	top := strings.Join(completionWords[""], " ")
	switch args[0] {
	case "bash", "zsh":
		var b strings.Builder
		if args[0] == "zsh" {
			b.WriteString("autoload -U +X bashcompinit && bashcompinit\n")
		}
		b.WriteString("_matii() {\n  local cur=${COMP_WORDS[COMP_CWORD]} words\n  if [ \"$COMP_CWORD\" -eq 1 ]; then words=\"" + top + "\"\n  else case \"${COMP_WORDS[1]}\" in\n")
		for _, cmd := range []string{"auth", "secrets", "dynamic", "dynamic-secrets", "users", "completion"} {
			fmt.Fprintf(&b, "    %s) [ \"$COMP_CWORD\" -eq 2 ] && words=%q ;;\n", cmd, strings.Join(completionWords[cmd], " "))
		}
		b.WriteString("  esac; fi\n  COMPREPLY=($(compgen -W \"$words\" -- \"$cur\"))\n}\ncomplete -o default -F _matii matii\n")
		fmt.Fprint(stdout, b.String())
	case "fish":
		fmt.Fprintf(stdout, "complete -c matii -f -n __fish_use_subcommand -a %q\n", top)
		for _, cmd := range []string{"auth", "secrets", "dynamic", "users", "completion"} {
			fmt.Fprintf(stdout, "complete -c matii -f -n '__fish_seen_subcommand_from %s' -a %q\n", cmd, strings.Join(completionWords[cmd], " "))
		}
	default:
		return usagef("usage: matii completion bash|zsh|fish")
	}
	return nil
}
