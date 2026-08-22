package golem

import (
	"context"
	"sort"
	"sync"
)

// Registry routes model names to the backend that serves them. It is the only
// thing the HTTP server and the CLI talk to, so neither has to know whether a
// request is about to run on this machine or in an AWS region.
type Registry struct {
	mu       sync.RWMutex
	order    []string
	backends map[string]Backend
	routes   map[string]Backend
	fallback string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		backends: make(map[string]Backend),
		routes:   make(map[string]Backend),
	}
}

// Register adds a backend and the model names it answers to. Later
// registrations win a name conflict, so config order decides precedence.
func (r *Registry) Register(b Backend, models []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.backends[b.Name()]; !ok {
		r.order = append(r.order, b.Name())
	}
	r.backends[b.Name()] = b
	for _, m := range models {
		r.routes[m] = b
	}
}

// SetDefault names the model used when a request does not specify one.
func (r *Registry) SetDefault(model string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = model
}

// Default returns the fallback model name, if one is configured.
func (r *Registry) Default() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fallback
}

// Resolve finds the backend for a model name, applying the default when the
// name is empty.
func (r *Registry) Resolve(model string) (Backend, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if model == "" {
		model = r.fallback
	}
	if b, ok := r.routes[model]; ok {
		return b, model, nil
	}
	return nil, model, &UnknownModelError{Model: model}
}

// Backend returns a registered backend by name.
func (r *Registry) Backend(name string) (Backend, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.backends[name]
	return b, ok
}

// Models asks every backend what it can serve. A backend that errors is
// skipped rather than failing the whole listing — one unreachable region
// should not hide the models running locally.
func (r *Registry) Models(ctx context.Context) []Model {
	r.mu.RLock()
	backends := make([]Backend, 0, len(r.backends))
	for _, name := range r.order {
		backends = append(backends, r.backends[name])
	}
	r.mu.RUnlock()

	var out []Model
	for _, b := range backends {
		models, err := b.Models(ctx)
		if err != nil {
			continue
		}
		out = append(out, models...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Close shuts every backend down, returning the first error.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	for _, name := range r.order {
		if err := r.backends[name].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
