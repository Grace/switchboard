// Package cli implements the switchboard command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Grace/switchboard/internal/backend/bedrock"
	"github.com/Grace/switchboard/internal/backend/local"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/switchboard"
)

// Stamped at build time with -ldflags. See .goreleaser.yaml and the Dockerfile,
// which must name this package path — pointing them at `main` is a mistake that
// only shows up as a release reporting "dev".
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// versionString renders whatever the build stamped.
func versionString() string {
	out := "switchboard " + Version
	switch {
	case Commit != "" && Date != "":
		out += " (" + Commit + ", " + Date + ")"
	case Commit != "":
		out += " (" + Commit + ")"
	}
	return out
}

const usage = `switchboard — run your own models, on your machine or in your cloud

usage: switchboard <command> [flags]

commands:
  serve      serve the HTTP API (OpenAI-compatible)
  run        talk to a model from the terminal
  models     list configured models
  connect    load a model into memory on a running server
  disconnect unload a model from a running server
  init       write a starter config file
  redact     check redaction rules against text on stdin
  audit      verify the audit chain, or reconstruct one decision
  agents     list the programs calling this gateway, as the traffic reveals them
  controls   assess this config against the control objectives a review asks about
  evidence   package a period of the log for someone who does not trust you
  version    print the version

run "switchboard <command> -h" for a command's flags.
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
	case "connect":
		err = runConnect(ctx, args[1:])
	case "disconnect":
		err = runDisconnect(ctx, args[1:])
	case "init":
		err = runInit(ctx, args[1:])
	case "redact":
		err = runRedact(ctx, args[1:])
	case "audit":
		err = runAudit(ctx, args[1:])
	case "agents":
		err = runAgents(ctx, args[1:])
	case "controls":
		err = runControls(ctx, args[1:])
	case "evidence":
		err = runEvidence(ctx, args[1:])
	case "version":
		fmt.Println(versionString())
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "switchboard: unknown command %q\n\n%s", cmd, usage)
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
		fmt.Fprintln(os.Stderr, "switchboard:", err)
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
		fmt.Fprintf(warn, "switchboard: no config at %s — run 'switchboard init' to create one\n", path)
	}
	return cfg, nil
}

// buildRegistry wires up one backend per kind of model the config mentions.
// Backends with no models are not constructed at all, so a laptop-only config
// never touches AWS and an AWS-only config never looks for llama-server.
func buildRegistry(cfg *config.Config) *switchboard.Registry {
	reg := switchboard.NewRegistry()

	if models := cfg.ModelsFor(config.BackendLocal); len(models) > 0 {
		reg.Register(local.New(local.Options{
			ServerPath:  cfg.Local.Server,
			Device:      cfg.Local.Device,
			IdleTimeout: cfg.Local.IdleTimeout.Duration(),
		}, models), names(models))
	}

	if models := cfg.ModelsFor(config.BackendBedrock); len(models) > 0 {
		reg.Register(bedrock.New(bedrock.Options{
			Region:      cfg.Bedrock.Region,
			Profile:     cfg.Bedrock.Profile,
			Attribution: cfg.Attribution,
		}, models), names(models))
	}

	reg.SetDefault(cfg.DefaultModel)
	return reg
}

func names(models []config.Line) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.Name)
	}
	return out
}

// configFlag registers the shared -config flag.
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", config.DefaultPath(), "path to switchboard.json")
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
