package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	src := "# comment\n\nexport A=1\nB = spaced value # comment\nC=\"multi\\nline \\\"q\\\"\"\nD='literal \\n $x'\nE=\"real\nnewline\"\nURL=http://x/#frag\n"
	got, err := parseDotenv(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []dotenvEntry{{"A", "1"}, {"B", "spaced value"}, {"C", "multi\nline \"q\""}, {"D", `literal \n $x`}, {"E", "real\nnewline"}, {"URL", "http://x/#frag"}}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q want %q", i, got[i], want[i])
		}
	}
	for _, bad := range []string{"NOEQUALS\n", "1BAD=x\n", "A=\"open\n", "A=\"x\" trailing\n"} {
		if _, err := parseDotenv(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestExportFormatsEscape(t *testing.T) {
	m := map[string]string{"TPL": "${HOME} %{x}", "Q": "a\"b\nc", "ODD KEY": "é=:"}
	checks := map[string][]string{
		"hcl":             {`TPL = "$${HOME} %%{x}"`, `Q = "a\"b\nc"`, `"ODD KEY" = "é=:"`},
		"yaml":            {`Q: "a\"b\nc"`},
		"toml":            {`TPL = "${HOME} %{x}"`},
		"java_properties": {"ODD\\ KEY=\\u00e9\\=\\:", `Q=a"b\nc`},
		"xml":             {`<secret name="Q">a&#34;b&#xA;c</secret>`},
		"csv":             {"Key,Value\n", "\"a\"\"b\nc\""},
		"ini":             {"[DEFAULT]\n", `Q = a"b\nc`},
	}
	for format, wants := range checks {
		out := exporters[format](m)
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q in\n%s", format, want, out)
			}
		}
	}
}

func TestRandomValues(t *testing.T) {
	cases := map[string]*regexp.Regexp{
		"hex":          regexp.MustCompile(`^[0-9a-f]{33}$`),
		"alphanumeric": regexp.MustCompile(`^[A-Za-z0-9]{33}$`),
		"base64":       regexp.MustCompile(`^[A-Za-z0-9+/]{33}$`),
		"base64url":    regexp.MustCompile(`^[A-Za-z0-9_-]{33}$`),
	}
	for kind, re := range cases {
		v, err := randomValue(kind, 33)
		if err != nil || !re.MatchString(v) {
			t.Errorf("%s: %q %v", kind, v, err)
		}
	}
	for kind, n := range map[string]int{"key128": 16, "key256": 32} {
		v, _ := randomValue(kind, 0+1)
		if b, err := base64.StdEncoding.DecodeString(v); err != nil || len(b) != n {
			t.Errorf("%s: %q", kind, v)
		}
	}
	if _, err := randomValue("nope", 10); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestProjectLookup(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	write := func(monorepo bool) {
		b := `{"version":"1","appId":"id1","appName":"Payments","defaultEnv":"development","monorepoSupport":` + map[bool]string{true: "true", false: "false"}[monorepo] + `}`
		if err := os.WriteFile(filepath.Join(root, projectFile), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(false)
	if _, _, err := findProject(); !os.IsNotExist(err) {
		t.Fatalf("a parent without monorepoSupport applied: %v", err)
	}
	write(true)
	p, _, err := findProject()
	if err != nil || p.AppID != "id1" {
		t.Fatalf("monorepo lookup: %v %+v", err, p)
	}
	for _, k := range []string{"MATII_APP", "MATII_APP_ID", "MATII_ENV"} {
		t.Setenv(k, "")
	}
	tg := &target{env: "staging"}
	if err := tg.complete(); err != nil || tg.appID != "id1" || tg.env != "staging" {
		t.Fatalf("flags must win over the file: %v %+v", err, tg)
	}
	t.Setenv("MATII_APP", "Other")
	tg = &target{}
	if err := tg.complete(); err != nil || tg.app != "Other" || tg.appID != "" || tg.env != "development" {
		t.Fatalf("MATII_APP must win over the file: %+v", tg)
	}
}

func TestParseArgsInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	app := fs.String("app", "", "")
	pos, after, dashed, err := parseArgs(fs, []string{"KEY", "--app", "A", "OTHER", "--", "cmd", "--app", "B"})
	if err != nil || *app != "A" || strings.Join(pos, ",") != "KEY,OTHER" || !dashed || strings.Join(after, " ") != "cmd --app B" {
		t.Fatalf("%v %q %q %v %v", err, *app, pos, after, dashed)
	}
	if _, _, _, err := parseArgs(fs, []string{"--nope"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestRunUsage(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"run", "--app", "a", "--env", "e", "two", "words"}, &bytes.Buffer{}, &stderr); code != 2 {
		t.Fatalf("unquoted multi-word command without -- should be a usage error, got %d", code)
	}
	var out bytes.Buffer
	if code := run([]string{"completion", "bash"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "complete -o default -F _matii matii") {
		t.Fatalf("completion: %d %s", code, out.String())
	}
}
