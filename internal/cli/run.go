package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/grace/golem/internal/golem"
)

func runRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	system := fs.String("system", "", "system prompt")
	maxTokens := fs.Int("max-tokens", 0, "cap the response length (0 = model default)")
	temperature := fs.Float64("temperature", -1, "sampling temperature (<0 = model default)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "usage: golem run [flags] [model] [prompt...]\n\n"+
			"With a prompt, prints one response. Without one, opens a chat;\n"+
			"piped stdin is read as the prompt.\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath, os.Stderr)
	if err != nil {
		return err
	}
	reg := buildRegistry(cfg)
	defer reg.Close()

	// The first argument is a model name only if it actually names one;
	// otherwise the whole tail is the prompt for the default model.
	rest := fs.Args()
	model := reg.Default()
	if len(rest) > 0 {
		if _, _, err := reg.Resolve(rest[0]); err == nil {
			model, rest = rest[0], rest[1:]
		}
	}

	backend, model, err := reg.Resolve(model)
	if err != nil {
		if model == "" {
			return errors.New("no model given and no default_model configured")
		}
		return err
	}

	opts := &golem.ChatRequest{Model: model, MaxTokens: *maxTokens}
	if *temperature >= 0 {
		opts.Temperature = temperature
	}
	if *system != "" {
		opts.Messages = append(opts.Messages, golem.Message{Role: golem.RoleSystem, Content: *system})
	}

	if prompt := strings.TrimSpace(strings.Join(rest, " ")); prompt != "" {
		return once(ctx, backend, opts, prompt)
	}
	if piped, err := readPipedStdin(); err != nil {
		return err
	} else if piped != "" {
		return once(ctx, backend, opts, piped)
	}
	return chat(ctx, backend, opts)
}

// once sends a single prompt and streams the answer to stdout.
func once(ctx context.Context, backend golem.Backend, base *golem.ChatRequest, prompt string) error {
	req := *base
	req.Messages = append(append([]golem.Message{}, base.Messages...),
		golem.Message{Role: golem.RoleUser, Content: prompt})

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	_, err := backend.Chat(ctx, &req, func(c golem.Chunk) error {
		_, err := out.WriteString(c.Text)
		// Flushing per chunk is what makes the response visibly stream rather
		// than land all at once when the buffer fills.
		out.Flush()
		return err
	})
	if err != nil {
		return err
	}
	out.WriteString("\n")
	return nil
}

// chat runs an interactive session, keeping the conversation in memory.
func chat(ctx context.Context, backend golem.Backend, base *golem.ChatRequest) error {
	req := *base
	req.Messages = append([]golem.Message{}, base.Messages...)

	fmt.Fprintf(os.Stderr, "%s — ctrl-d to leave\n\n", req.Model)
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	out := bufio.NewWriter(os.Stdout)

	for {
		fmt.Fprint(os.Stderr, "› ")
		if !in.Scan() {
			fmt.Fprintln(os.Stderr)
			return in.Err()
		}
		prompt := strings.TrimSpace(in.Text())
		if prompt == "" {
			continue
		}

		req.Messages = append(req.Messages, golem.Message{Role: golem.RoleUser, Content: prompt})
		result, err := backend.Chat(ctx, &req, func(c golem.Chunk) error {
			out.WriteString(c.Text)
			out.Flush()
			return nil
		})
		out.WriteString("\n\n")
		out.Flush()

		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// One failed turn should not end the session; drop the turn that
			// went nowhere so the history stays consistent.
			fmt.Fprintln(os.Stderr, "golem:", err)
			req.Messages = req.Messages[:len(req.Messages)-1]
			continue
		}
		req.Messages = append(req.Messages, golem.Message{Role: golem.RoleAssistant, Content: result.Text})
	}
}

// readPipedStdin returns stdin's contents when it is a pipe or file, and "" if
// it is a terminal.
func readPipedStdin() (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return "", nil
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return "", nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
