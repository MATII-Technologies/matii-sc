package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string     { return fmt.Sprint(*l) }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// secretEnv returns os.Environ() plus the target's secrets and leased dynamic
// credentials (secrets override inherited variables of the same name).
func secretEnv(t *target, dynamic []string, ttl time.Duration) ([]string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	secrets, err := fetch(ctx, t)
	if err != nil {
		return nil, 0, err
	}
	env := os.Environ()
	values := matii.Map(secrets)
	for k, v := range values {
		env = append(env, k+"="+v)
	}
	count := len(values)
	if len(dynamic) > 0 {
		client, err := newClient()
		if err != nil {
			return nil, 0, err
		}
		for _, name := range dynamic {
			lease, err := client.LeaseDynamic(ctx, t.query(), name, ttl)
			if err != nil {
				return nil, 0, fmt.Errorf("dynamic secret %s: %w", name, err)
			}
			for k, v := range lease.Credentials {
				env = append(env, k+"="+v)
				count++
			}
		}
	}
	return env, count, nil
}

// runCommand executes a program with the environment's secrets in its
// environment: `matii run [flags] -- program args...`, or a single command
// string run by the shell: `matii run "npm run dev"`.
func runCommand(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	t := addTarget(fs)
	var dynamic stringList
	fs.Var(&dynamic, "dynamic", "dynamic secret to lease into the environment (repeatable)")
	ttl := fs.Duration("ttl", 0, "lease duration for --dynamic, e.g. 30m (default: the definition's)")
	pos, argv, dashed, err := parseArgs(fs, args)
	if err != nil {
		return exitCode(err, stderr)
	}
	switch {
	case dashed && len(pos) == 0 && len(argv) > 0:
	case !dashed && len(pos) == 1:
		argv = shellCommandLine(pos[0])
	default:
		fmt.Fprintln(stderr, `usage: matii run [--app APP] [--env ENV] -- command [args...]
       matii run [--app APP] [--env ENV] "command string"`)
		return 2
	}
	if err := t.complete(); err != nil {
		return exitCode(err, stderr)
	}
	env, _, err := secretEnv(t, dynamic, *ttl)
	if err != nil {
		return exitCode(err, stderr)
	}
	return execWithEnv(argv, env, stderr)
}

// shellCommandLine runs a command string with the platform shell.
func shellCommandLine(command string) []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/C", command}
	}
	return []string{"/bin/sh", "-c", command}
}

// execWithEnv runs argv with env, forwarding signals, and returns its exit code.
func execWithEnv(argv, env []string, stderr io.Writer) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "matii:", err)
		return 127
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range signals {
			_ = cmd.Process.Signal(sig)
		}
	}()
	err := cmd.Wait()
	signal.Stop(signals)
	close(signals)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

// shellCommand opens an interactive shell with the secrets in its environment.
func shellCommand(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	t := addTarget(fs)
	shell := fs.String("shell", "", "shell to start (default: $SHELL)")
	pos, _, _, err := parseArgs(fs, args)
	if err != nil {
		return exitCode(err, stderr)
	}
	if len(pos) > 0 {
		fmt.Fprintln(stderr, "usage: matii shell [--shell bash|zsh|fish|...] [--app APP] [--env ENV]")
		return 2
	}
	if err := t.complete(); err != nil {
		return exitCode(err, stderr)
	}
	if os.Getenv("MATII_SHELL") != "" {
		fmt.Fprintln(stderr, "matii: already inside a matii shell; type exit to leave it first")
		return 1
	}
	program := *shell
	if program == "" {
		program = os.Getenv("SHELL")
	}
	if program == "" {
		program = "/bin/sh"
		if runtime.GOOS == "windows" {
			program = os.Getenv("COMSPEC")
		}
	}
	if resolved, err := exec.LookPath(program); err == nil {
		program = resolved
	}
	env, count, err := secretEnv(t, nil, 0)
	if err != nil {
		return exitCode(err, stderr)
	}
	label := t.app
	if label == "" {
		label = t.appID
	}
	env = append(env, "MATII_SHELL=1", "MATII_SHELL_APP="+label, "MATII_SHELL_ENV="+t.env)
	fmt.Fprintf(stderr, "matii: %s shell with %d secret(s) from %s (%s). Type exit to leave.\n", filepath.Base(program), count, label, t.env)
	code := execWithEnv([]string{program}, env, stderr)
	fmt.Fprintln(stderr, "matii: left the shell; its secrets are gone with it.")
	return code
}
