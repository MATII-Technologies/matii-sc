package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakePlugin(t *testing.T, name, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugins")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "matii-"+name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestPackageCommandsForwardToMatiiPkg(t *testing.T) {
	fakePlugin(t, "pkg", `echo "pkg:$*"; exit 7`)
	var out, errOut bytes.Buffer
	if code := run([]string{"install", "--frozen-lockfile"}, &out, &errOut); code != 7 || strings.TrimSpace(out.String()) != "pkg:install --frozen-lockfile" {
		t.Fatalf("forward: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := run([]string{"pkg", "init", "@acme/x"}, &out, &errOut); code != 7 || strings.TrimSpace(out.String()) != "pkg:init @acme/x" {
		t.Fatalf("pkg prefix: code=%d out=%q", code, out.String())
	}
	// Built-in commands are never shadowed by plugins.
	out.Reset()
	if code := run([]string{"version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "matii ") {
		t.Fatalf("built-in version shadowed: %q", out.String())
	}
}

func TestGenericPluginsAndUnknown(t *testing.T) {
	fakePlugin(t, "hello", `echo "hi $1"`)
	var out, errOut bytes.Buffer
	if code := run([]string{"hello", "there"}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "hi there" {
		t.Fatalf("plugin: %d %q", code, out.String())
	}
	if code := run([]string{"no-such-thing"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("unknown: %d %q", code, errOut.String())
	}
	if code := run([]string{"../evil"}, &out, &errOut); code != 2 {
		t.Fatal("path-like plugin names must be refused")
	}
}
