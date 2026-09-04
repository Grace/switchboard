package switchboard

import (
	"context"
	"errors"
	"testing"
)

type stubBackend struct {
	name     string
	models   []Model
	listErr  error
	closeErr error
	closed   int
}

func (s *stubBackend) Name() string { return s.name }
func (s *stubBackend) Models(context.Context) ([]Model, error) {
	return s.models, s.listErr
}
func (s *stubBackend) Chat(context.Context, *ChatRequest, func(Chunk) error) (*Result, error) {
	return &Result{}, nil
}
func (s *stubBackend) Close() error { s.closed++; return s.closeErr }

func model(name, backend string) Model { return Model{Name: name, Backend: backend} }

// Shutdown has to reach every backend. A registry that closes the first and
// stops leaves a llama.cpp process holding several gigabytes of weights, and
// nothing later notices.
func TestCloseReachesEveryBackend(t *testing.T) {
	a := &stubBackend{name: "a"}
	b := &stubBackend{name: "b", closeErr: errors.New("b failed")}
	c := &stubBackend{name: "c"}

	r := NewRegistry()
	r.Register(a, []string{"m1"})
	r.Register(b, []string{"m2"})
	r.Register(c, []string{"m3"})

	err := r.Close()
	if err == nil || err.Error() != "b failed" {
		t.Errorf("Close should return the first error, got %v", err)
	}
	for _, s := range []*stubBackend{a, b, c} {
		if s.closed != 1 {
			t.Errorf("backend %s closed %d times; a failure must not stop the rest", s.name, s.closed)
		}
	}
}

func TestCloseIsQuietWhenNothingFails(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubBackend{name: "a"}, []string{"m"})
	if err := r.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestDefaultRoundTrips(t *testing.T) {
	r := NewRegistry()
	if got := r.Default(); got != "" {
		t.Errorf("a fresh registry has no default, got %q", got)
	}
	r.SetDefault("qwen")
	if got := r.Default(); got != "qwen" {
		t.Errorf("Default() = %q", got)
	}
}

func TestBackendLookupByName(t *testing.T) {
	a := &stubBackend{name: "local"}
	r := NewRegistry()
	r.Register(a, []string{"m"})

	got, ok := r.Backend("local")
	if !ok || got != Backend(a) {
		t.Errorf("Backend(%q) = %v, %v", "local", got, ok)
	}
	if _, ok := r.Backend("bedrock"); ok {
		t.Error("an unregistered name must not resolve")
	}
}

// Resolving with no name and no default is a different failure from resolving
// an unknown name, and the caller reports them differently.
func TestResolveFallsBackToDefault(t *testing.T) {
	a := &stubBackend{name: "a"}
	r := NewRegistry()
	r.Register(a, []string{"qwen"})
	r.SetDefault("qwen")

	b, name, err := r.Resolve("")
	if err != nil || name != "qwen" || b != Backend(a) {
		t.Fatalf("Resolve(\"\") = %v, %q, %v", b, name, err)
	}

	_, name, err = r.Resolve("nope")
	var unknown *UnknownModelError
	if !errors.As(err, &unknown) {
		t.Fatalf("want UnknownModelError, got %T", err)
	}
	if name != "nope" {
		t.Errorf("the offending name should come back for the error message, got %q", name)
	}
	if !errors.Is(err, err) || unknown.Model != "nope" {
		t.Errorf("error should carry the model, got %+v", unknown)
	}
}

// One unreachable region must not hide the models running on your desk.
func TestModelsSkipsBackendsThatError(t *testing.T) {
	up := &stubBackend{name: "local", models: []Model{model("qwen", "local")}}
	down := &stubBackend{name: "bedrock", listErr: errors.New("no credentials")}

	r := NewRegistry()
	r.Register(up, []string{"qwen"})
	r.Register(down, []string{"opus"})

	got := r.Models(context.Background())
	if len(got) != 1 || got[0].Name != "qwen" {
		t.Fatalf("models = %+v, want only the reachable backend's", got)
	}
}

func TestModelsAreSortedByName(t *testing.T) {
	a := &stubBackend{name: "a", models: []Model{model("zeta", "a"), model("alpha", "a")}}
	b := &stubBackend{name: "b", models: []Model{model("mid", "b")}}

	r := NewRegistry()
	r.Register(a, []string{"zeta", "alpha"})
	r.Register(b, []string{"mid"})

	got := r.Models(context.Background())
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("models = %+v", got)
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("models[%d] = %q, want %q", i, got[i].Name, name)
		}
	}
}

func TestUnknownModelErrorReads(t *testing.T) {
	err := &UnknownModelError{Model: "ghost"}
	if got := err.Error(); got == "" {
		t.Error("error message must not be empty")
	}
	if !errors.As(error(err), new(*UnknownModelError)) {
		t.Error("should match itself via errors.As")
	}
}
