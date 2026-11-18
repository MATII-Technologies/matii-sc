package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

// Plugins: adera dispatches commands it does not implement to separate
// executables, git-style, so other Matii tools ship independently:
//
//	adera pkg <args>        -> matii-pkg <args>  (Matii Package Platform CLI)
//	adera add|install|...   -> matii-pkg add|install|...  (package commands
//	                           whose names do not collide with secret commands)
//	adera <name> <args>     -> adera-<name> <args>  (any other plugin on PATH)
//
// Plugins are looked up next to the adera executable first, then on PATH.
// Commands adera itself implements (init, update, version, auth, ...) always
// win; the package CLI's versions stay reachable as "adera pkg <command>".

// packageCommands are forwarded to matii-pkg without the "pkg" prefix.
var packageCommands = map[string]bool{
	"add": true, "remove": true, "install": true, "list": true, "search": true, "info": true, "publish": true,
	"unpublish": true, "deprecate": true, "yank": true, "pack": true, "audit": true, "verify": true, "sbom": true, "key": true,
	"login": true, "logout": true, "whoami": true, "org": true, "team": true, "package": true, "token": true, "registry": true,
	"doctor": true, "create": true, "project": true, "device": true, "config": true, "cache": true,
}

var pluginName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// findPlugin returns the path of adera-<name> (matii-pkg for pkg).
func findPlugin(name string) (string, error) {
	if !pluginName.MatchString(name) {
		return "", errors.New("invalid plugin name")
	}
	exe := "adera-" + name
	if name == "pkg" {
		exe = "matii-pkg" // the Matii Package Platform CLI keeps its own name
	}
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), exe)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return exec.LookPath(exe)
}

// runPlugin runs a plugin with the remaining arguments, passing stdio
// through, and returns its exit code. ok is false when no plugin exists.
func runPlugin(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (code int, ok bool) {
	path, err := findPlugin(name)
	if err != nil {
		return 0, false
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), true
		}
		fmt.Fprintf(stderr, "adera: running %s: %v\n", path, err)
		return 1, true
	}
	return 0, true
}

// dispatchPlugin handles "adera pkg ..." and unknown commands.
func dispatchPlugin(args []string, stdout, stderr io.Writer) (int, bool) {
	if args[0] == "pkg" {
		if code, ok := runPlugin("pkg", args[1:], os.Stdin, stdout, stderr); ok {
			return code, true
		}
		fmt.Fprintln(stderr, "adera: the package CLI (matii-pkg) is not installed; see the Matii Package Platform docs")
		return 127, true
	}
	if packageCommands[args[0]] {
		if code, ok := runPlugin("pkg", args, os.Stdin, stdout, stderr); ok {
			return code, true
		}
	}
	return runPlugin(args[0], args[1:], os.Stdin, stdout, stderr)
}
