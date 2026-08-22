// Command golem runs language models on your own machine or in your own
// cloud, behind one OpenAI-compatible API.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/grace/golem/internal/cli"
)

func main() {
	// One interrupt cancels the work in flight; a second one is left to the
	// runtime, so a wedged model can always be killed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(cli.Main(ctx, os.Args[1:]))
}
