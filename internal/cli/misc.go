package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/grace/golem/internal/config"
)

func runModels(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("models", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath, os.Stderr)
	if err != nil {
		return err
	}
	reg := buildRegistry(cfg)
	defer reg.Close()

	models := reg.Models(ctx)
	if len(models) == 0 {
		fmt.Println("no models configured — run 'golem init' to start a config")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MODEL\tBACKEND\tSTATE\tDETAIL")
	for _, m := range models {
		state := "clay"
		if m.Live {
			state = "animated"
		}
		mark := ""
		if m.Name == reg.Default() {
			mark = " (default)"
		}
		fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\n", m.Name, mark, m.Backend, state, m.Detail)
	}
	return w.Flush()
}

func runAnimate(ctx context.Context, args []string) error {
	return adminCommand(ctx, "animate", args)
}

func runRest(ctx context.Context, args []string) error {
	return adminCommand(ctx, "rest", args)
}

// adminCommand drives the server's load/unload endpoints. These act on a
// running server rather than in-process, since the whole point is to change
// what the serving process is holding in memory.
func adminCommand(ctx context.Context, verb string, args []string) error {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	cfgPath := configFlag(fs)
	server := fs.String("server", "", "server address (default: listen address from config)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: golem %s <model>", verb)
	}

	addr := *server
	if addr == "" {
		cfg, err := loadConfig(*cfgPath, nil)
		if err != nil {
			return err
		}
		addr = cfg.Listen
	}
	url := normalizeURL(addr) + "/v1/" + verb

	body, err := json.Marshal(map[string]string{"model": fs.Arg(0)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("no server at %s (start one with 'golem serve'): %w", addr, err)
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var wrapped struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(payload, &wrapped) == nil && wrapped.Error.Message != "" {
			return errors.New(wrapped.Error.Message)
		}
		return fmt.Errorf("server returned %s", resp.Status)
	}

	var state struct {
		Model  string `json:"model"`
		State  string `json:"state"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return err
	}
	if state.Detail != "" {
		fmt.Printf("%s: %s — %s\n", state.Model, state.State, state.Detail)
	} else {
		fmt.Printf("%s: %s\n", state.Model, state.State)
	}
	return nil
}

func normalizeURL(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	if !bytes.Contains([]byte(addr), []byte("://")) {
		addr = "http://" + addr
	}
	return addr
}

func runInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	force := fs.Bool("force", false, "overwrite an existing config")
	if err := parse(fs, args); err != nil {
		return err
	}

	if _, err := os.Stat(*cfgPath); err == nil && !*force {
		return fmt.Errorf("%s already exists (pass -force to overwrite)", *cfgPath)
	}

	cfg := config.Default()
	cfg.DefaultModel = "claude-sonnet"
	cfg.Models = []config.Shem{
		{
			Name:    "claude-sonnet",
			Backend: config.BackendBedrock,
			ModelID: "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		},
		{
			Name:    "local",
			Backend: config.BackendLocal,
			Path:    "~/models/your-model.gguf",
			Context: 8192,
		},
	}
	if cfg.Bedrock.Region == "" {
		cfg.Bedrock.Region = "us-east-1"
	}

	if err := cfg.Save(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n\nnext:\n"+
		"  - point the \"local\" model at a .gguf file you have, or delete it\n"+
		"  - check the bedrock region and model id, or delete that entry\n"+
		"  - golem models\n", *cfgPath)
	return nil
}
