package switchboard

import "context"

// Caller is the identity switchboard resolved for a request.
//
// A gateway authenticates its callers at its own layer and then calls the
// provider under one service role, which is exactly the distinction the
// provider's bill can no longer see. Carrying the caller through to the backend
// is what lets a backend put it back.
type Caller struct {
	// Team is the attribution unit — whatever the bill should be split by.
	Team string
	// Subject identifies the individual, when the caller proved who they are
	// rather than only which team they belong to. Empty for a shared team key.
	Subject string
}

type callerKey struct{}

// WithCaller returns a context carrying the resolved caller.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the caller on the context, if the request was attributed.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}
