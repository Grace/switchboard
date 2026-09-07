// Command loadgen drives sustained load through the gateway.
//
// It exists because the gateway speaks server-sent events, which general purpose
// HTTP benchmarking tools do not consume correctly: they report a response as
// complete at the headers, so a streaming generation looks instant and the
// numbers are meaningless. This reads each stream to completion and counts the
// frames, so a streaming request is measured over its whole life.
//
// Standard library only, so it adds nothing to the module's dependency graph.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type result struct {
	status  int
	latency time.Duration
	frames  int
	err     error
}

type stats struct {
	mu        sync.Mutex
	latencies []time.Duration
	byStatus  map[int]int
	transport int
	frames    int64
}

func (s *stats) add(r result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.err != nil {
		s.transport++
		return
	}
	s.latencies = append(s.latencies, r.latency)
	s.byStatus[r.status]++
	s.frames += int64(r.frames)
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

func main() {
	url := flag.String("url", "http://127.0.0.1:8080", "gateway base URL")
	token := flag.String("token", os.Getenv("LOCAL_TOKEN"), "bearer token; defaults to $LOCAL_TOKEN")
	concurrency := flag.Int("concurrency", 8, "concurrent workers")
	duration := flag.Duration("duration", 30*time.Second, "how long to sustain load")
	streamPct := flag.Int("stream-pct", 50, "percentage of requests that stream")
	maxTokens := flag.Int("max-tokens", 64, "max_tokens per request")
	timeout := flag.Duration("timeout", 120*time.Second, "per-request timeout")
	rps := flag.Int("rps", 0, "cap offered load at this rate; 0 offers as fast as workers allow")
	label := flag.String("label", "", "label printed with the report")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "no token: pass -token or set LOCAL_TOKEN")
		os.Exit(2)
	}

	// One shared client so connection reuse is exercised the way a real caller
	// would exercise it.
	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency * 2,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	deadline, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()

	s := &stats{byStatus: map[int]int{}}
	var sent atomic.Int64
	started := time.Now()

	// Offered-load throttle. Without it every run simply measures the gateway's
	// rate limiter, which is only interesting when that is what is being tested.
	var ticks <-chan time.Time
	if *rps > 0 {
		t := time.NewTicker(time.Second / time.Duration(*rps))
		defer t.Stop()
		ticks = t.C
	}

	var wg sync.WaitGroup
	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for deadline.Err() == nil {
				if ticks != nil {
					select {
					case <-ticks:
					case <-deadline.Done():
						return
					}
				}
				n := sent.Add(1)
				stream := int(n%100) < *streamPct
				s.add(one(deadline, client, *url, *token, stream, *maxTokens))
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(started)

	s.mu.Lock()
	defer s.mu.Unlock()
	sort.Slice(s.latencies, func(i, j int) bool { return s.latencies[i] < s.latencies[j] })

	total := len(s.latencies) + s.transport
	ok := s.byStatus[200]
	if *label != "" {
		fmt.Printf("\n== %s ==\n", *label)
	}
	offered := "uncapped"
	if *rps > 0 {
		offered = fmt.Sprintf("%d/s", *rps)
	}
	fmt.Printf("duration        %s (workers %d, stream %d%%, offered %s)\n",
		elapsed.Round(10*time.Millisecond), *concurrency, *streamPct, offered)
	fmt.Printf("requests        %d  (%.1f/s)\n", total, float64(total)/elapsed.Seconds())
	fmt.Printf("succeeded       %d\n", ok)
	fmt.Printf("failed          %d  (%.2f%% error rate)\n",
		total-ok, 100*float64(total-ok)/float64(max(total, 1)))
	if s.transport > 0 {
		fmt.Printf("transport errs  %d  (no HTTP response at all)\n", s.transport)
	}
	fmt.Printf("sse frames      %d\n", s.frames)
	fmt.Printf("latency p50     %s\n", percentile(s.latencies, 0.50).Round(time.Millisecond))
	fmt.Printf("latency p95     %s\n", percentile(s.latencies, 0.95).Round(time.Millisecond))
	fmt.Printf("latency p99     %s\n", percentile(s.latencies, 0.99).Round(time.Millisecond))
	fmt.Print("status codes    ")
	codes := make([]int, 0, len(s.byStatus))
	for c := range s.byStatus {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, fmt.Sprintf("%d=%d", c, s.byStatus[c]))
	}
	fmt.Println(strings.Join(parts, "  "))

	// A run whose requests all failed is not a successful load test.
	if ok == 0 && total > 0 {
		os.Exit(1)
	}
}

func one(ctx context.Context, client *http.Client, base, token string, stream bool, maxTokens int) result {
	body, _ := json.Marshal(map[string]any{
		"model":      "preferred",
		"stream":     stream,
		"max_tokens": maxTokens,
		"messages":   []map[string]string{{"role": "user", "content": "load"}},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return result{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	begin := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return result{err: err, latency: time.Since(begin)}
	}
	defer resp.Body.Close()

	frames := 0
	if stream && resp.StatusCode == 200 {
		// Read the stream to completion. Stopping at the headers would report a
		// generation as instantaneous.
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data:") {
				frames++
			}
		}
	} else {
		io.Copy(io.Discard, resp.Body)
	}
	return result{status: resp.StatusCode, latency: time.Since(begin), frames: frames}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
