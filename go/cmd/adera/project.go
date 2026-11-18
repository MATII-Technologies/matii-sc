package main

// Project configuration: `adera init` links a directory to an app and a
// default environment by writing .adera.json. Commands look for it in the
// current directory, then in parent directories whose file sets
// monorepoSupport (so one file at a monorepo root covers every package).

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

const projectFile = ".adera.json"

// maxProjectDepth is how many parent directories are searched.
const maxProjectDepth = 8

type project struct {
	Version         string `json:"version"`
	AppID           string `json:"appId"`
	AppName         string `json:"appName"`
	DefaultEnv      string `json:"defaultEnv"`
	EnvID           string `json:"envId"`
	MonorepoSupport bool   `json:"monorepoSupport"`
}

// findProject returns the project configuration that applies to the current
// directory, and its path; os.ErrNotExist if there is none.
func findProject() (*project, string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, "", err
	}
	for depth := 0; depth <= maxProjectDepth; depth++ {
		path := filepath.Join(dir, projectFile)
		b, err := os.ReadFile(path)
		if err == nil {
			var p project
			if err := json.Unmarshal(b, &p); err != nil || (p.AppID == "" && p.AppName == "") {
				return nil, path, fmt.Errorf("%s is not valid; run adera init again", path)
			}
			if depth == 0 || p.MonorepoSupport {
				return &p, path, nil
			}
			return nil, "", os.ErrNotExist
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, path, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil, "", os.ErrNotExist
}

func initCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	app := fs.String("app", "", "app name")
	appID := fs.String("app-id", "", "app id")
	env := fs.String("env", "", "default environment")
	monorepo := fs.Bool("monorepo", false, "also apply to subdirectories")
	force := fs.Bool("force", false, "overwrite an existing .adera.json")
	if pos, _, _, err := parseArgs(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("usage: adera init [--app APP | --app-id ID] [--env ENV] [--monorepo]")
	}
	if _, err := os.Stat(projectFile); err == nil && !*force {
		if !isTerminal(os.Stdin) {
			return usagef("%s already exists; use --force to replace it", projectFile)
		}
		answer, err := prompt(stderr, projectFile+" already exists. Replace it? [y/N] ")
		if err != nil || !strings.EqualFold(strings.TrimSpace(answer), "y") {
			return errors.New("cancelled")
		}
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	apps, err := client.Apps(ctx)
	if err != nil {
		return err
	}
	if len(apps) == 0 {
		return errors.New("this account has no access to any app; create one in the console or ask for access")
	}
	var chosen *matii.App
	switch {
	case *appID != "" || *app != "":
		for i := range apps {
			if apps[i].ID == *appID || (*appID == "" && strings.EqualFold(apps[i].Name, *app)) {
				chosen = &apps[i]
			}
		}
		if chosen == nil {
			return errors.New("this account has no access to that app")
		}
	default:
		names := make([]string, len(apps))
		for i, a := range apps {
			names[i] = a.Name
		}
		i, err := choose(stderr, "Apps", names)
		if err != nil {
			return err
		}
		chosen = &apps[i]
	}
	if len(chosen.Environments) == 0 {
		return fmt.Errorf("this account has no access to any environment of %s", chosen.Name)
	}
	var environment *matii.Environment
	if *env != "" {
		_, e, err := client.EnvironmentOf(ctx, matii.Query{AppID: chosen.ID, Env: *env})
		if err != nil {
			return err
		}
		environment = e
	} else {
		names := make([]string, len(chosen.Environments))
		for i, e := range chosen.Environments {
			names[i] = e.Name
		}
		i, err := choose(stderr, "Default environment", names)
		if err != nil {
			return err
		}
		environment = &chosen.Environments[i]
	}
	if !*monorepo && !*force && *app == "" && *appID == "" && isTerminal(os.Stdin) {
		answer, _ := prompt(stderr, "Use this configuration in subdirectories too (monorepo)? [y/N] ")
		*monorepo = strings.EqualFold(strings.TrimSpace(answer), "y")
	}
	b, _ := json.MarshalIndent(project{
		Version: "1", AppID: chosen.ID, AppName: chosen.Name, DefaultEnv: environment.Name, EnvID: environment.ID,
		MonorepoSupport: *monorepo,
	}, "", "  ")
	if err := os.WriteFile(projectFile, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Linked this directory to %s (%s). Wrote %s; it holds no secrets and can be committed.\n", chosen.Name, environment.Name, projectFile)
	return nil
}
