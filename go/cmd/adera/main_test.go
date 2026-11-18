package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

func TestGithubEnvMasksBeforeExporting(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ENV", envFile)
	var out bytes.Buffer
	secrets := []matii.Secret{{Key: "PEM", Value: "-----BEGIN-----\nabc\n-----END-----"}, {Key: "H", Redacted: true}}
	if err := githubEnv(secrets, &out); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"-----BEGIN-----", "abc", "-----END-----"} {
		if !strings.Contains(out.String(), "::add-mask::"+line+"\n") {
			t.Fatalf("line %q not masked: %s", line, out.String())
		}
	}
	written, _ := os.ReadFile(envFile)
	if !strings.HasPrefix(string(written), "PEM<<ADERA_EOF_") || !strings.Contains(string(written), "\nabc\n") {
		t.Fatalf("env file: %q", written)
	}
	if strings.Contains(string(written), "H<<") {
		t.Fatal("redacted secret exported")
	}
}

func TestUsageErrors(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"secrets", "list"}, &bytes.Buffer{}, &stderr); code == 0 {
		t.Fatal("expected failure without --app/--env")
	}
	if code := run([]string{"run", "--app", "a", "--env", "e"}, &bytes.Buffer{}, &stderr); code != 2 {
		t.Fatal("run without -- should be a usage error")
	}
}
