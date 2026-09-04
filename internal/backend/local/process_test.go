package local

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/switchboard"
)

// The process lifecycle is the part a first-time user actually meets: the model
// takes thirty seconds to load and either becomes ready or hangs. Testing it
// needs a real child process, so this test binary re-executes itself as a
// stand-in for llama-server.
//
// TestFakeLlamaServer below is that stand-in. It is a no-op unless the
// environment variable is set, so it costs nothing on a normal run.
const fakeServerEnv = "SWITCHBOARD_FAKE_LLAMA"

func TestFakeLlamaServer(t *testing.T) {
	mode := os.Getenv(fakeServerEnv)
	if mode == "" {
		t.Skip("helper process; runs only when re-executed by another test")
	}

	fs := flag.NewFlagSet("fake", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	port := fs.String("port", "0", "")
	host := fs.String("host", "127.0.0.1", "")
	for _, ignore := range []string{"model", "n-gpu-layers", "ctx-size"} {
		fs.String(ignore, "", "")
	}
	// os.Args carries the test binary's own flags first; take everything after
	// the separator the parent inserted.
	args := os.Args[1:]
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	_ = fs.Parse(args)

	switch mode {
	case "exit":
		// A model that fails to load: exit before ever serving /health.
		os.Exit(3)
	case "hang":
		// Never becomes healthy.
		select {}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"pong\"}}]}\n\ndata: [DONE]\n\n")
	})
	_ = http.ListenAndServe(*host+":"+*port, mux)
}

// fakeServerScript writes a shim that re-executes this test binary as the
// helper above, so exec.LookPath and the real argv are exercised.
func fakeServerScript(t *testing.T, mode string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "llama-server")
	script := fmt.Sprintf(
		"#!/bin/sh\nexec %q -test.run '^TestFakeLlamaServer$' -- \"$@\"\n", self)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeServerEnv, mode)
	return path
}

func modelFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(p, []byte("not really weights"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func newBackend(t *testing.T, mode string, idle time.Duration) (*Backend, config.Line) {
	t.Helper()
	spec := config.Line{
		Name: "test-model", Backend: config.BackendLocal,
		Path: modelFile(t), Context: 2048,
	}
	b := New(Options{
		ServerPath:  fakeServerScript(t, mode),
		Host:        "127.0.0.1",
		IdleTimeout: idle,
		Logf:        func(string, ...any) {},
	}, []config.Line{spec})
	t.Cleanup(func() { b.Close() })
	return b, spec
}

// The happy path end to end: spawn a process, poll it to healthy, serve a
// completion through it, and shut it down.
func TestStartsServesAndStops(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell")
	}
	b, _ := newBackend(t, "serve", 0)

	var got []string
	res, err := b.Chat(context.Background(), &switchboard.ChatRequest{
		Model:    "test-model",
		Messages: []switchboard.Message{{Role: switchboard.RoleUser, Content: "ping"}},
	}, func(c switchboard.Chunk) error { got = append(got, c.Text); return nil })
	if err != nil {
		t.Fatalf("Chat through a spawned process: %v", err)
	}
	if res.Text != "pong" {
		t.Errorf("text = %q", res.Text)
	}

	models, _ := b.Models(context.Background())
	if len(models) != 1 || !models[0].Live {
		t.Errorf("model should report Live once started: %+v", models)
	}

	if !b.Disconnect("test-model") {
		t.Error("Disconnect should report that it stopped something")
	}
	if b.Disconnect("test-model") {
		t.Error("Disconnect twice should report nothing to stop")
	}
}

// A model that dies during load must surface as an error rather than hanging
// until the health-check ceiling.
func TestProcessThatExitsDuringLoadFailsFast(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell")
	}
	b, _ := newBackend(t, "exit", 0)

	start := time.Now()
	_, err := b.Chat(context.Background(), &switchboard.ChatRequest{Model: "test-model"},
		func(switchboard.Chunk) error { return nil })
	if err == nil {
		t.Fatal("expected an error when the server exits during load")
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("took %s; a dead process should be noticed, not waited out", elapsed)
	}
}

// Giving up is the caller's prerogative: a cancelled context must stop the
// wait rather than running to the ceiling.
func TestContextCancellationStopsTheWait(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell")
	}
	b, _ := newBackend(t, "hang", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := b.Chat(ctx, &switchboard.ChatRequest{Model: "test-model"},
		func(switchboard.Chunk) error { return nil })
	if err == nil {
		t.Fatal("expected an error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("took %s; cancellation should be honoured promptly", elapsed)
	}
}

// A missing model file is a configuration mistake, and the message has to name
// the model — "no such file" alone sends someone hunting.
func TestMissingModelFileNamesTheModel(t *testing.T) {
	spec := config.Line{Name: "ghost", Backend: config.BackendLocal, Path: "/nonexistent/model.gguf"}
	b := New(Options{ServerPath: fakeServerScript(t, "serve"), Logf: func(string, ...any) {}},
		[]config.Line{spec})
	t.Cleanup(func() { b.Close() })

	_, err := b.Chat(context.Background(), &switchboard.ChatRequest{Model: "ghost"},
		func(switchboard.Chunk) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("error should name the model, got %v", err)
	}
}

func TestMissingServerBinaryIsActionable(t *testing.T) {
	spec := config.Line{Name: "m", Backend: config.BackendLocal, Path: modelFile(t)}
	b := New(Options{ServerPath: "definitely-not-on-path-12345", Logf: func(string, ...any) {}},
		[]config.Line{spec})
	t.Cleanup(func() { b.Close() })

	_, err := b.Chat(context.Background(), &switchboard.ChatRequest{Model: "m"},
		func(switchboard.Chunk) error { return nil })
	if err == nil {
		t.Fatal("expected an error")
	}
	// The message should say how to fix it, not just that exec failed.
	if !strings.Contains(err.Error(), "local.server") {
		t.Errorf("error should point at the config key, got %v", err)
	}
}
