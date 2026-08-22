// Package local runs models on this machine.
//
// It drives llama.cpp's llama-server as a child process, one per animated
// model, and proxies chat over its OpenAI-compatible endpoint. Going through
// the binary rather than binding libllama with cgo keeps golem a pure-Go
// static build while inheriting llama.cpp's device support unchanged: Metal on
// Apple silicon, CUDA on a desktop or an external GPU, plain CPU everywhere
// else. A cgo backend can be dropped in later behind the same interface.
package local

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grace/golem/internal/config"
	"github.com/grace/golem/internal/golem"
	"github.com/grace/golem/internal/wire"
)

// Options configures the backend.
type Options struct {
	// ServerPath is the llama-server binary. Looked up on PATH if empty.
	ServerPath string
	// Device is auto, metal, cuda, gpu, or cpu.
	Device string
	// IdleTimeout unloads a model after this long unused. Zero disables it.
	IdleTimeout time.Duration
	// Host is the loopback address child servers bind to.
	Host string
	// Logf receives lifecycle messages. Defaults to stderr.
	Logf func(format string, args ...any)
}

// Backend is a golem.Backend that runs models locally.
type Backend struct {
	opts   Options
	client *http.Client

	mu    sync.Mutex
	specs map[string]config.Shem
	order []string
	live  map[string]*instance

	stopOnce sync.Once
	stop     chan struct{}
}

// instance is one running llama-server. Exactly one goroutine calls Wait on
// cmd; everything else observes the exit by reading done.
type instance struct {
	spec     config.Shem
	cmd      *exec.Cmd
	base     string
	started  time.Time
	lastUsed time.Time
	inflight int

	done    chan struct{}
	waitErr error
}

var _ golem.Backend = (*Backend)(nil)

// New builds a backend serving the given shems.
func New(opts Options, models []config.Shem) *Backend {
	if opts.Host == "" {
		opts.Host = "127.0.0.1"
	}
	if opts.Device == "" {
		opts.Device = "auto"
	}
	if opts.Logf == nil {
		opts.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "golem: "+format+"\n", args...)
		}
	}

	b := &Backend{
		opts:  opts,
		specs: make(map[string]config.Shem, len(models)),
		live:  make(map[string]*instance),
		stop:  make(chan struct{}),
		// No client timeout: generation is long-lived and streaming. Callers
		// bound the work with the request context instead.
		client: &http.Client{},
	}
	for _, m := range models {
		b.specs[m.Name] = m
		b.order = append(b.order, m.Name)
	}

	if opts.IdleTimeout > 0 {
		go b.reap()
	}
	return b
}

// Name implements golem.Backend.
func (b *Backend) Name() string { return config.BackendLocal }

// Models implements golem.Backend.
func (b *Backend) Models(context.Context) ([]golem.Model, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]golem.Model, 0, len(b.order))
	for _, name := range b.order {
		spec := b.specs[name]
		inst, live := b.live[name]
		detail := config.ExpandPath(spec.Path)
		if live {
			detail = fmt.Sprintf("%s (animated %s)", detail, time.Since(inst.started).Round(time.Second))
		}
		out = append(out, golem.Model{
			Name:    name,
			Backend: b.Name(),
			Detail:  detail,
			Live:    live,
		})
	}
	return out, nil
}

// Chat implements golem.Backend.
func (b *Backend) Chat(ctx context.Context, req *golem.ChatRequest, emit func(golem.Chunk) error) (*golem.Result, error) {
	inst, err := b.ensure(ctx, req.Model)
	if err != nil {
		return nil, err
	}
	b.acquire(inst)
	defer b.release(inst)

	body, err := json.Marshal(toWire(req))
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, inst.base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llama-server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("llama-server returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	return readSSE(resp.Body, emit)
}

// toWire converts a neutral request into llama-server's dialect.
func toWire(req *golem.ChatRequest) wire.ChatRequest {
	out := wire.ChatRequest{
		Model:         req.Model,
		Messages:      make([]wire.Message, 0, len(req.Messages)),
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		Stop:          req.Stop,
		Stream:        true,
		StreamOptions: &wire.StreamOptions{IncludeUsage: true},
	}
	for _, m := range req.Messages {
		out.Messages = append(out.Messages, wire.Message{Role: string(m.Role), Content: m.Content})
	}
	return out
}

// readSSE consumes an OpenAI-style event stream, emitting each delta.
func readSSE(r io.Reader, emit func(golem.Chunk) error) (*golem.Result, error) {
	scanner := bufio.NewScanner(r)
	// Individual frames can carry a large final chunk; give the scanner room.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var text strings.Builder
	result := &golem.Result{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			break
		}

		var frame wire.ChatResponse
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			// A malformed frame is a bug upstream, not a reason to lose the
			// tokens already streamed.
			continue
		}
		if frame.Usage != nil {
			result.Usage = golem.Usage{
				InputTokens:  frame.Usage.PromptTokens,
				OutputTokens: frame.Usage.CompletionTokens,
			}
		}
		for _, choice := range frame.Choices {
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				result.StopReason = *choice.FinishReason
			}
			if choice.Delta == nil || choice.Delta.Content == "" {
				continue
			}
			text.WriteString(choice.Delta.Content)
			if err := emit(golem.Chunk{Text: choice.Delta.Content}); err != nil {
				return nil, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading stream: %w", err)
	}

	result.Text = text.String()
	return result, nil
}

// Animate loads a model into memory ahead of the first request, so that the
// wait for weights to load does not land on a user.
func (b *Backend) Animate(ctx context.Context, name string) error {
	_, err := b.ensure(ctx, name)
	return err
}

// ensure starts a model if it is not already running and waits for it to
// answer health checks.
func (b *Backend) ensure(ctx context.Context, name string) (*instance, error) {
	b.mu.Lock()
	if inst, ok := b.live[name]; ok {
		inst.lastUsed = time.Now()
		b.mu.Unlock()
		return inst, nil
	}
	spec, ok := b.specs[name]
	if !ok {
		b.mu.Unlock()
		return nil, &golem.UnknownModelError{Model: name}
	}
	b.mu.Unlock()

	inst, err := b.start(ctx, spec)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	// Another caller may have won the race while we were starting; keep theirs
	// and shut ours down rather than leaking a process.
	if existing, ok := b.live[name]; ok {
		go halt(inst)
		existing.lastUsed = time.Now()
		return existing, nil
	}
	b.live[name] = inst
	return inst, nil
}

// start launches llama-server and blocks until it is healthy.
func (b *Backend) start(ctx context.Context, spec config.Shem) (*instance, error) {
	bin := b.opts.ServerPath
	if bin == "" {
		bin = "llama-server"
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("llama-server not found (set local.server in config, or install llama.cpp): %w", err)
	}

	path := config.ExpandPath(spec.Path)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("model %q: %w", spec.Name, err)
	}

	port, err := freePort(b.opts.Host)
	if err != nil {
		return nil, err
	}

	args := []string{
		"--model", path,
		"--host", b.opts.Host,
		"--port", strconv.Itoa(port),
		"--n-gpu-layers", gpuLayers(b.opts.Device, spec.GPULayers),
	}
	if spec.Context > 0 {
		args = append(args, "--ctx-size", strconv.Itoa(spec.Context))
	}
	args = append(args, spec.Args...)

	// Deliberately not bound to the request context: the process outlives the
	// request that started it and is torn down by Rest, the reaper, or Close.
	cmd := exec.Command(resolved, args...)
	cmd.Stdout = prefixWriter{prefix: "[" + spec.Name + "] ", w: os.Stderr}
	cmd.Stderr = cmd.Stdout
	configureProcess(cmd)

	b.opts.Logf("animating %s on port %d", spec.Name, port)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting llama-server: %w", err)
	}

	inst := &instance{
		spec:     spec,
		cmd:      cmd,
		base:     fmt.Sprintf("http://%s:%d", b.opts.Host, port),
		started:  time.Now(),
		lastUsed: time.Now(),
		done:     make(chan struct{}),
	}
	go func() {
		inst.waitErr = cmd.Wait()
		close(inst.done)
	}()

	if err := b.waitHealthy(ctx, inst); err != nil {
		halt(inst)
		return nil, err
	}
	b.opts.Logf("%s ready in %s", spec.Name, time.Since(inst.started).Round(time.Millisecond))
	return inst, nil
}

// waitHealthy polls until the server reports ready, the process exits, or the
// caller gives up. Large models take a while to load, so the ceiling is
// generous.
func (b *Backend) waitHealthy(ctx context.Context, inst *instance) error {
	deadline := time.NewTimer(10 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-inst.done:
			return fmt.Errorf("llama-server exited while loading %s: %v", inst.spec.Name, inst.waitErr)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for %s to load", inst.spec.Name)
		case <-tick.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, inst.base+"/health", nil)
			if err != nil {
				return err
			}
			resp, err := b.client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}
}

// Rest unloads a model, freeing its memory. It is a no-op if the model is not
// running.
func (b *Backend) Rest(name string) bool {
	b.mu.Lock()
	inst, ok := b.live[name]
	if ok {
		delete(b.live, name)
	}
	b.mu.Unlock()

	if !ok {
		return false
	}
	b.opts.Logf("resting %s", name)
	halt(inst)
	return true
}

// halt asks a model to exit, escalating to SIGKILL if it will not. Signals go
// to the whole process group: llama-server may have spawned helpers, and a
// stranded child would hold the GPU.
func halt(inst *instance) {
	select {
	case <-inst.done:
		return
	default:
	}

	signalGroup(inst.cmd, os.Interrupt)
	select {
	case <-inst.done:
		return
	case <-time.After(5 * time.Second):
	}

	signalGroup(inst.cmd, os.Kill)
	select {
	case <-inst.done:
	case <-time.After(5 * time.Second):
	}
}

// reap unloads models that have gone idle.
func (b *Backend) reap() {
	interval := b.opts.IdleTimeout / 4
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-b.stop:
			return
		case <-tick.C:
			b.mu.Lock()
			var idle []string
			for name, inst := range b.live {
				if inst.inflight == 0 && time.Since(inst.lastUsed) > b.opts.IdleTimeout {
					idle = append(idle, name)
				}
			}
			b.mu.Unlock()

			for _, name := range idle {
				b.opts.Logf("%s idle for %s", name, b.opts.IdleTimeout)
				b.Rest(name)
			}
		}
	}
}

func (b *Backend) acquire(inst *instance) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inst.inflight++
	inst.lastUsed = time.Now()
}

func (b *Backend) release(inst *instance) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inst.inflight--
	inst.lastUsed = time.Now()
}

// Close stops every running model.
func (b *Backend) Close() error {
	b.stopOnce.Do(func() { close(b.stop) })

	b.mu.Lock()
	live := b.live
	b.live = make(map[string]*instance)
	b.mu.Unlock()

	var wg sync.WaitGroup
	for _, inst := range live {
		wg.Add(1)
		go func(inst *instance) {
			defer wg.Done()
			halt(inst)
		}(inst)
	}
	wg.Wait()
	return nil
}

// gpuLayers decides how much of the model to offload. An explicit config value
// always wins; otherwise the device setting decides, and "auto" means "use the
// GPU if this machine plausibly has a usable one".
func gpuLayers(device string, override *int) string {
	if override != nil {
		return strconv.Itoa(*override)
	}
	switch device {
	case "cpu":
		return "0"
	case "metal", "cuda", "gpu":
		return "999"
	default:
		if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
			return "999"
		}
		if _, err := exec.LookPath("nvidia-smi"); err == nil {
			return "999"
		}
		return "0"
	}
}

// freePort asks the kernel for an unused port. There is an unavoidable window
// between closing the listener and the child binding it; in practice the
// kernel does not hand the same port out twice that quickly.
func freePort(host string) (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// prefixWriter tags child output so several models' logs stay legible when
// interleaved.
type prefixWriter struct {
	prefix string
	w      io.Writer
}

func (p prefixWriter) Write(b []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		fmt.Fprintf(p.w, "%s%s\n", p.prefix, line)
	}
	return len(b), nil
}
