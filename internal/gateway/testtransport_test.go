package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

// Restricted CI/agent environments may run identical handler scenarios without
// binding sockets. Normal test execution always uses real loopback HTTP servers.
var testHandlers sync.Map

type testEndpoint struct {
	URL   string
	close func()
}

func (e *testEndpoint) Close() { e.close() }
func testHTTP(t *testing.T, h http.Handler) *testEndpoint {
	t.Helper()
	if os.Getenv("SWITCHBOARD_IN_MEMORY_TESTS") != "1" {
		s := httptest.NewServer(h)
		return &testEndpoint{s.URL, s.Close}
	}
	host := randomID(8) + ".test"
	testHandlers.Store(host, h)
	return &testEndpoint{"http://" + host, func() { testHandlers.Delete(host) }}
}

type memoryTransport struct{}

func (memoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	h, ok := testHandlers.Load(r.URL.Host)
	if !ok {
		return nil, errors.New("mock endpoint unavailable")
	}
	if e := r.Context().Err(); e != nil {
		return nil, e
	}
	w := httptest.NewRecorder()
	h.(http.Handler).ServeHTTP(w, r)
	res := w.Result()
	res.Request = r
	return res, nil
}
func useTestTransport(c *http.Client) {
	if os.Getenv("SWITCHBOARD_IN_MEMORY_TESTS") == "1" {
		c.Transport = memoryTransport{}
	}
}
