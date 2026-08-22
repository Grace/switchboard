// Package cli implements the golem command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/grace/golem/internal/backend/bedrock"
	"github.com/grace/golem/internal/backend/local"
	"github.com/grace/golem/internal/config"
	"github.com/grace/golem/internal/golem"
)

// Version is stamped at build time with -ldflags.
var Version = "dev"

const usage = `golem — run your own models, on your machine or in your cloud

usage: golem <command> [flags]

commands:
  serve      serve the HTTP API (OpenAI-compatible)
  run        talk to a model from the terminal
  models     list configured models
  animate    load a model into memory on a running server
  rest       unload a model from a running server
  init       write a starter config file
  version    print the version

run "golem <command> -h" for a command's flags.
`

// Main runs the CLI and returns a process exit code.
func Main(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	var err error
	switch cmd := args[0]; cmd {
	case "serve":
		err = runServe(ctx, args[1:])
	case "run":
		err = runRun(ctx, args[1:])
	case "models":
		err = runModels(ctx, args[1:])
	case "animate":
		err = runAnimate(ctx, args[1:])
	case "rest":
		err = runRest(ctx, args[1:])
	case "init":
		err = runInit(ctx, args[1:])
	case "version":
		fmt.Println("golem", Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "golem: unknown command %q\n\n%s", cmd, usage)
		return 2
	}

	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, context.Canceled):
		// Ctrl-C is a normal way to end a generation, not a failure.
		return 0
	default:
		fmt.Fprintln(os.Stderr, "golem:", err)
		return 1
	}
}

// loadConfig reads the config file, telling the user where it looked when the
// roster turns out to be empty.
func loadConfig(path string, warn io.Writer) (*config.Config, error) {
	cfg, found, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if !found && warn != nil {
		fmt.Fprintf(warn, "golem: no config at %s — run 'golem init' to create one\n", path)
	}
	return cfg, nil
}

// buildRegistry wires up one backend per kind of model the config mentions.
// Backends with no models are not constructed at all, so a laptop-only config
// never touches AWS and an AWS-only config never looks for llama-server.
func buildRegistry(cfg *config.Config) *golem.Registry {
	reg := golem.NewRegistry()

	if models := cfg.ModelsFor(config.BackendLocal); len(models) > 0 {
		reg.Register(local.New(local.Options{
			ServerPath:  cfg.Local.Server,
			Device:      cfg.Local.Device,
			IdleTimeout: cfg.Local.IdleTimeout.Duration(),
		}, models), names(models))
	}

	if models := cfg.ModelsFor(config.BackendBedrock); len(models) > 0 {
		reg.Register(bedrock.New(bedrock.Options{
			Region:  cfg.Bedrock.Region,
			Profile: cfg.Bedrock.Profile,
		}, models), names(models))
	}

	reg.SetDefault(cfg.DefaultModel)
	return reg
}

func names(models []config.Shem) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.Name)
	}
	return out
}

// configFlag registers the shared -config flag.
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", config.DefaultPath(), "path to golem.json")
}

// parse runs a flag set, converting the help case into flag.ErrHelp so Main
// can exit quietly.
func parse(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return flag.ErrHelp
		}
		return err
	}
	return nil
}
