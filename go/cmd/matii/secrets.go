package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/matii-org/matii-secret-clients/go/matii"
)

func secretsCommand(ctx context.Context, sub string, args []string, stdout, stderr io.Writer) error {
	switch sub {
	case "list":
		return secretsList(ctx, args, stdout)
	case "get":
		return secretsGet(ctx, args, stdout)
	case "create":
		return secretsCreate(ctx, args, stdout, stderr)
	case "update":
		return secretsUpdate(ctx, args, stdout, stderr)
	case "delete":
		return secretsDelete(ctx, args, stdout, stderr)
	case "import":
		return secretsImport(ctx, args, stdout)
	case "export":
		return secretsExport(ctx, args, stdout)
	}
	return usagef("unknown command %q (list, get, create, update, delete, import, export)", sub)
}

// targetArgs parses the target flags plus extra ones and completes the target.
func targetArgs(name string, args []string, extra func(fs *flag.FlagSet)) (*target, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	t := addTarget(fs)
	if extra != nil {
		extra(fs)
	}
	pos, _, _, err := parseArgs(fs, args)
	if err != nil {
		return nil, nil, err
	}
	if err := t.complete(); err != nil {
		return nil, nil, err
	}
	return t, pos, nil
}

// fetch returns the environment's secrets with references resolved and
// personal overrides applied, filtered by --tags.
func fetch(ctx context.Context, t *target) ([]matii.Secret, error) {
	client, err := newClient()
	if err != nil {
		return nil, err
	}
	secrets, err := client.Secrets(ctx, t.query())
	if err != nil {
		return nil, err
	}
	want := t.tagList()
	kept := secrets[:0]
	for _, s := range secrets {
		if hasTag(s.Tags, want) {
			kept = append(kept, s)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Path+kept[i].Key < kept[j].Path+kept[j].Key })
	return kept, nil
}

func pathPrefix(path string) string {
	if path == "" || path == "/" {
		return ""
	}
	return strings.TrimSuffix(path, "/") + "/"
}

// --- list / get ------------------------------------------------------------------

func secretsList(ctx context.Context, args []string, stdout io.Writer) error {
	var show bool
	t, pos, err := targetArgs("list", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&show, "show", false, "show values")
	})
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("usage: matii secrets list [--show] [--app APP] [--env ENV] [--path PATH] [--tags a,b]")
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	app, env, err := client.EnvironmentOf(ctx, t.query())
	if err != nil {
		return err
	}
	stored, err := client.ListSecrets(ctx, t.query())
	if err != nil {
		return err
	}
	want := t.tagList()
	sort.SliceStable(stored, func(i, j int) bool { return stored[i].Path+stored[i].Key < stored[j].Path+stored[j].Key })
	fmt.Fprintf(stdout, "%s · %s (%s)\n\n", app.Name, env.Name, map[string]string{"SSE": "server-side encrypted", "E2E": "end-to-end encrypted"}[app.Encryption])
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tVALUE\tPATH\tTAGS\tCOMMENT\tNOTES")
	count := 0
	for _, s := range stored {
		if !hasTag(s.Tags, want) {
			continue
		}
		count++
		value, notes := s.Value, []string{}
		if s.Override != nil && s.Override.Active {
			value = s.Override.Value
			notes = append(notes, "personal override")
		}
		if strings.Contains(value, "${") {
			notes = append(notes, "reference")
		}
		if s.Type != "" && s.Type != "secret" {
			notes = append(notes, s.Type)
		}
		switch {
		case s.Redacted:
			value = "(no reveal permission)"
		case s.Type == "sealed":
			value = "(sealed)"
		case !show && s.Type != "config":
			value = mask(value)
		default:
			value = oneLine(value, 60)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Key, value, s.Path, strings.Join(s.Tags, ","), oneLine(s.Comment, 40), strings.Join(notes, ", "))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if count == 0 {
		fmt.Fprintln(stdout, "(no secrets)")
	} else if !show {
		fmt.Fprintf(stdout, "\n%d secret(s). Values are hidden; use --show to see them.\n", count)
	}
	return nil
}

func mask(v string) string {
	if v == "" {
		return ""
	}
	return "********" // fixed width: the length of a value is not shown either
}

func oneLine(v string, max int) string {
	v = strings.NewReplacer("\r", `\r`, "\n", `\n`, "\t", `\t`).Replace(v)
	if r := []rune(v); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return v
}

func secretsGet(ctx context.Context, args []string, stdout io.Writer) error {
	var format string
	t, pos, err := targetArgs("get", args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "format", "value", "value|json")
	})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: matii secrets get KEY [--format value|json] [--app APP] [--env ENV] [--path PATH]")
	}
	if format != "value" && format != "json" {
		return usagef("--format must be value or json")
	}
	secrets, err := fetch(ctx, t)
	if err != nil {
		return err
	}
	key := strings.ToUpper(pos[0])
	// Without --path, a key in the root folder wins over one in a subfolder.
	sort.SliceStable(secrets, func(i, j int) bool { return secrets[i].Path == "/" && secrets[j].Path != "/" })
	for _, s := range secrets {
		if s.Key != key {
			continue
		}
		if s.Redacted {
			return errors.New("you may list this secret but not reveal its value")
		}
		if format == "json" {
			b, _ := json.MarshalIndent(map[string]any{
				"key": s.Key, "value": s.Value, "path": s.Path, "comment": s.Comment,
				"tags": nonNilTags(s.Tags), "type": s.Type, "overridden": s.Overridden,
			}, "", "  ")
			fmt.Fprintln(stdout, string(b))
			return nil
		}
		fmt.Fprintln(stdout, s.Value)
		return nil
	}
	return fmt.Errorf("secret %q not found", pos[0])
}

func nonNilTags(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	return tags
}

// --- create / update / delete ---------------------------------------------------------

// valueFlags are the ways a new value can be supplied.
type valueFlags struct {
	random   string
	length   int
	override bool
}

func (v *valueFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&v.random, "random", "", "generate the value: hex, alphanumeric, base64, base64url, key128 or key256")
	fs.IntVar(&v.length, "length", 32, "length of a generated value (hex, alphanumeric, base64, base64url)")
	fs.BoolVar(&v.override, "override", false, "set your personal override instead of the shared value")
}

// randomValue generates a value of the given kind; length counts characters.
func randomValue(kind string, length int) (string, error) {
	if length < 1 || length > 4096 {
		return "", usagef("--length must be between 1 and 4096")
	}
	bytesFor := func(n int) ([]byte, error) {
		b := make([]byte, n)
		_, err := rand.Read(b)
		return b, err
	}
	switch kind {
	case "hex":
		b, err := bytesFor((length + 1) / 2)
		return hex.EncodeToString(b)[:length], err
	case "base64", "base64url":
		b, err := bytesFor(length)
		enc := base64.StdEncoding
		if kind == "base64url" {
			enc = base64.RawURLEncoding
		}
		return enc.EncodeToString(b)[:length], err
	case "alphanumeric":
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		out := make([]byte, length)
		for i := range out {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return "", err
			}
			out[i] = alphabet[n.Int64()]
		}
		return string(out), nil
	case "key128", "key256":
		n := 16
		if kind == "key256" {
			n = 32
		}
		b, err := bytesFor(n)
		return base64.StdEncoding.EncodeToString(b), err
	}
	return "", usagef("--random must be hex, alphanumeric, base64, base64url, key128 or key256")
}

// readValue gets a value from --random, piped stdin or a hidden prompt.
func (v *valueFlags) read(stderr io.Writer, label string) (string, error) {
	if v.random != "" {
		return randomValue(v.random, v.length)
	}
	if !isTerminal(os.Stdin) {
		return readStdin()
	}
	return promptSecret(stderr, label)
}

func validType(t string) error {
	switch t {
	case "", "secret", "sealed", "config":
		return nil
	}
	return usagef("--type must be secret, sealed or config")
}

// requireUser rejects personal overrides for service accounts.
func requireUser(ctx context.Context, client *matii.Client) error {
	who, err := client.Whoami(ctx)
	if err != nil {
		return err
	}
	if who.Kind != "User" {
		return errors.New("personal overrides belong to people; sign in with matii auth login to use them")
	}
	return nil
}

func secretsCreate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var v valueFlags
	var comment, typ string
	t, pos, err := targetArgs("create", args, func(fs *flag.FlagSet) {
		v.register(fs)
		fs.StringVar(&comment, "comment", "", "comment")
		fs.StringVar(&typ, "type", "secret", "secret, sealed (write-only) or config (not secret)")
	})
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usagef("usage: matii secrets create [KEY] [--random TYPE] [--length N] [--comment TEXT] [--tags a,b] [--path PATH]")
	}
	if err := validType(typ); err != nil {
		return err
	}
	key := ""
	if len(pos) == 1 {
		key = pos[0]
	} else if isTerminal(os.Stdin) {
		if key, err = prompt(stderr, "Key: "); err != nil {
			return err
		}
	}
	key = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(key), " ", "_"))
	if key == "" {
		return usagef("a key is required: matii secrets create KEY")
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	if v.override {
		if err := requireUser(ctx, client); err != nil {
			return err
		}
	}
	value, err := v.read(stderr, "Value for "+key+": ")
	if err != nil {
		return err
	}
	secret := matii.StoredSecret{Key: key, Value: value, Comment: comment, Tags: t.tagList(), Type: typ, Path: t.path}
	if v.override {
		secret.Value, secret.Override = "", &matii.Override{Value: value, Active: true}
	}
	if err := client.CreateSecrets(ctx, t.query(), []matii.StoredSecret{secret}); err != nil {
		var apiErr *matii.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 409 {
			return fmt.Errorf("%s already exists in %s; use matii secrets update", key, displayPath(t.path))
		}
		return err
	}
	fmt.Fprintf(stdout, "Created %s%s.\n", pathPrefix(normalizePath(t.path)), key)
	return nil
}

func displayPath(p string) string { return normalizePath(p) }

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	return "/" + strings.Trim(p, "/")
}

// findStored returns the secret named key in the target's folder (default "/").
func findStored(ctx context.Context, client *matii.Client, t *target, key string) (*matii.StoredSecret, error) {
	q := t.query()
	q.Path = normalizePath(t.path)
	stored, err := client.ListSecrets(ctx, q)
	if err != nil {
		return nil, err
	}
	key = strings.ToUpper(key)
	for i := range stored {
		if stored[i].Key == key && stored[i].Path == q.Path {
			return &stored[i], nil
		}
	}
	return nil, fmt.Errorf("secret %s not found in %s", key, q.Path)
}

func secretsUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var v valueFlags
	var newPath, comment, typ string
	var toggle bool
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	t := addTarget(fs)
	v.register(fs)
	fs.StringVar(&newPath, "updated-path", "", "move the secret to this folder")
	fs.StringVar(&comment, "comment", "", "new comment")
	fs.StringVar(&typ, "type", "", "new type: secret, sealed or config")
	fs.BoolVar(&toggle, "toggle-override", false, "turn your personal override on or off")
	pos, _, _, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := t.complete(); err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: matii secrets update KEY [--random TYPE] [--updated-path PATH] [--comment TEXT] [--override] [--toggle-override]")
	}
	if err := validType(typ); err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	client, err := newClient()
	if err != nil {
		return err
	}
	if v.override || toggle {
		if err := requireUser(ctx, client); err != nil {
			return err
		}
	}
	s, err := findStored(ctx, client, t, pos[0])
	if err != nil {
		return err
	}
	changed := []string{}
	if set["updated-path"] {
		s.Path = normalizePath(newPath)
		changed = append(changed, "moved to "+s.Path)
	}
	if set["comment"] {
		s.Comment = comment
		changed = append(changed, "comment")
	}
	if set["tags"] {
		s.Tags = t.tagList()
		changed = append(changed, "tags")
	}
	if set["type"] {
		s.Type = typ
		changed = append(changed, "type")
	}
	if toggle {
		if s.Override == nil {
			return errors.New("you have no personal override for this secret; set one with --override")
		}
		s.Override.Active = !s.Override.Active
		changed = append(changed, map[bool]string{true: "override on", false: "override off"}[s.Override.Active])
	}
	// A new value is read when asked for (--random, --override) or when
	// nothing else changes.
	if v.random != "" || v.override || len(changed) == 0 {
		if s.Type == "sealed" && !v.override {
			return errors.New("sealed secrets cannot be changed; delete and recreate it")
		}
		value, err := v.read(stderr, "New value for "+s.Key+": ")
		if err != nil {
			return err
		}
		if value == "" && !isTerminal(os.Stdin) && v.random == "" {
			return errors.New("no value on stdin; pipe the new value, e.g. echo -n VALUE | matii secrets update KEY")
		}
		if v.override {
			s.Override = &matii.Override{Value: value, Active: true}
			changed = append(changed, "personal override")
		} else {
			if s.Redacted {
				s.Redacted = false // writing a value does not need Secrets:reveal
			}
			s.Value = value
			changed = append(changed, "value")
		}
	}
	if err := client.UpdateSecrets(ctx, t.query(), []matii.StoredSecret{*s}); err != nil {
		var apiErr *matii.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 409 {
			return fmt.Errorf("%s already exists in %s", s.Key, s.Path)
		}
		return err
	}
	fmt.Fprintf(stdout, "Updated %s%s (%s).\n", pathPrefix(s.Path), s.Key, strings.Join(changed, ", "))
	return nil
}

func secretsDelete(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	t, pos, err := targetArgs("delete", args, nil)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usagef("usage: matii secrets delete KEY... [--path PATH]")
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	q := t.query()
	q.Path = normalizePath(t.path)
	stored, err := client.ListSecrets(ctx, q)
	if err != nil {
		return err
	}
	byKey := map[string]string{}
	for _, s := range stored {
		if s.Path == q.Path {
			byKey[s.Key] = s.ID
		}
	}
	var ids, deleted, missing []string
	for _, k := range pos {
		k = strings.ToUpper(k)
		if id, ok := byKey[k]; ok {
			ids, deleted = append(ids, id), append(deleted, k)
			delete(byKey, k)
		} else {
			missing = append(missing, k)
		}
	}
	if err := client.DeleteSecrets(ctx, q, ids); err != nil {
		return err
	}
	if len(deleted) > 0 {
		fmt.Fprintf(stdout, "Deleted %s from %s.\n", strings.Join(deleted, ", "), q.Path)
	}
	if len(missing) > 0 {
		return fmt.Errorf("not found in %s: %s", q.Path, strings.Join(missing, ", "))
	}
	return nil
}

// --- import / export ---------------------------------------------------------------

func secretsImport(ctx context.Context, args []string, stdout io.Writer) error {
	t, pos, err := targetArgs("import", args, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: matii secrets import FILE|- [--path PATH] [--tags a,b]")
	}
	var data []byte
	if pos[0] == "-" {
		data, err = io.ReadAll(io.LimitReader(stdin, 16<<20))
	} else {
		data, err = os.ReadFile(pos[0])
	}
	if err != nil {
		return err
	}
	entries, err := parseDotenv(string(data))
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("no KEY=VALUE lines found")
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	q := t.query()
	q.Path = normalizePath(t.path)
	stored, err := client.ListSecrets(ctx, q)
	if err != nil {
		return err
	}
	existing := map[string]matii.StoredSecret{}
	for _, s := range stored {
		if s.Path == q.Path {
			existing[s.Key] = s
		}
	}
	var creates, updates []matii.StoredSecret
	seen := map[string]int{}
	for _, e := range entries {
		key := strings.ToUpper(e.key)
		if s, ok := existing[key]; ok {
			if s.Type == "sealed" {
				return fmt.Errorf("%s is sealed and cannot be changed by import", key)
			}
			s.Value, s.Redacted = e.value, false
			if t.tags != "" {
				s.Tags = t.tagList()
			}
			updates = append(updates, s)
			continue
		}
		if i, ok := seen[key]; ok { // later lines win, as in a shell
			creates[i].Value = e.value
			continue
		}
		seen[key] = len(creates)
		creates = append(creates, matii.StoredSecret{Key: key, Value: e.value, Path: q.Path, Tags: t.tagList()})
	}
	if err := client.CreateSecrets(ctx, q, creates); err != nil {
		return err
	}
	if err := client.UpdateSecrets(ctx, q, updates); err != nil {
		return fmt.Errorf("created %d secret(s), then updating failed: %w", len(creates), err)
	}
	fmt.Fprintf(stdout, "Imported %d secret(s) into %s: %d created, %d updated.\n", len(creates)+len(updates), q.Path, len(creates), len(updates))
	return nil
}

func secretsExport(ctx context.Context, args []string, stdout io.Writer) error {
	var format string
	t, keys, err := targetArgs("export", args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "format", "dotenv", "dotenv|json|csv|yaml|xml|toml|hcl|ini|java_properties|kv|shell|github")
	})
	if err != nil {
		return err
	}
	if _, ok := exporters[format]; !ok && format != "github" {
		return usagef("--format must be one of %s or github", strings.Join(exportFormats(), ", "))
	}
	secrets, err := fetch(ctx, t)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		want := map[string]bool{}
		for _, k := range keys {
			want[strings.ToUpper(k)] = true
		}
		kept := secrets[:0]
		for _, s := range secrets {
			if want[s.Key] {
				kept = append(kept, s)
			}
		}
		secrets = kept
	}
	if format == "github" {
		return githubEnv(secrets, stdout)
	}
	fmt.Fprint(stdout, exporters[format](matii.Map(secrets)))
	return nil
}
