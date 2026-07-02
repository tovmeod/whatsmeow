// 55.1-13: DownloadMediaWithPath host-failover handling.
//
// Root-cause of the 272-hit prod class (driver_log_class, WARN, download.go:277,
// "Failed to download media: invalid checksum length: expected 32, got 0, trying with next
// host..."): NOT a network/host problem. "invalid checksum length" was raised by the OLD
// hard `len(checksum) != 32` precondition in downloadEncryptedMedia /
// downloadEncryptedMediaToFile whenever a legitimate inbound media item's fileEncSHA256 was
// absent (len 0) -- a shape the ingest path allows. Because the failure was a validation
// error on the request parameters, not a per-host condition, EVERY host in the loop hit the
// identical error, burning the whole host list on media that could never succeed via
// failover. That precondition was already removed in this same session (commits 818322a
// "restore tolerant guard for missing plaintext hash" and 0ae1d5b "tolerate absent
// fileEncSHA256 in downloadEncryptedMedia{,ToFile} (2nd D-04 guard)", see
// download_regression_test.go) -- grepping the current tree and go.mod dependency cache for
// "invalid checksum length" returns zero hits. So the specific defect behind this historical
// burst is already fixed; what remains for this plan is the general host-failover WARN
// handling below (recovered vs exhausted counting), which is correctness work independent of
// that specific burst's root cause.
//
// This file covers that remaining handling: an intermediate host failure that a later host
// recovers must be counted (hostFailoverRecovered) and logged at Debug, never Warn; a failure
// that exhausts every host must keep the existing loud error return and count
// hostFailoverExhausted.

package whatsmeow

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// hostFailoverCaptureLogger records Warnf/Debugf calls so a test can assert the failover
// loop demotes intermediate failures to Debug and never emits a Warn for them. Distinct type
// from sender_key_converged_test.go's captureLogger (which is Infof-only) to avoid changing
// that file's behavior for unrelated tests.
type hostFailoverCaptureLogger struct {
	mu    sync.Mutex
	warn  []string
	debug []string
}

func (l *hostFailoverCaptureLogger) Warnf(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warn = append(l.warn, fmt.Sprintf(msg, args...))
}
func (l *hostFailoverCaptureLogger) Debugf(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debug = append(l.debug, fmt.Sprintf(msg, args...))
}
func (l *hostFailoverCaptureLogger) Infof(string, ...interface{})  {}
func (l *hostFailoverCaptureLogger) Errorf(string, ...interface{}) {}
func (l *hostFailoverCaptureLogger) Sub(string) waLog.Logger       { return l }

func (l *hostFailoverCaptureLogger) warnCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.warn)
}

func (l *hostFailoverCaptureLogger) debugCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.debug)
}

// hostRoundTripFunc is one host's canned behavior for multiHostTransport.
type hostRoundTripFunc func(req *http.Request) (*http.Response, error)

// multiHostTransport dispatches by request hostname to a per-host canned response/error,
// without binding any real listener -- lets the test assign arbitrary host.Hostname values
// (as mediaConn.Hosts would carry) without DNS.
type multiHostTransport struct {
	byHost map[string]hostRoundTripFunc
}

func (t *multiHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fn, ok := t.byHost[req.URL.Hostname()]
	if !ok {
		return nil, fmt.Errorf("no handler for host %q", req.URL.Hostname())
	}
	return fn(req)
}

func okResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

// errorResponse returns a non-2xx HTTP response (not a transport-level Go error). This
// matters for test determinism: http.Client.Do wraps any error a RoundTripper returns in a
// *url.Error, which always structurally satisfies net.Error regardless of the wrapped
// error's type -- that would route through downloadPossiblyEncryptedMediaWithRetries's
// separate 5-attempt network-retry loop (a different, slower retry path this test isn't
// exercising) before ever reaching the host-failover loop under test. A real HTTP response
// with a non-retryable status code (anything other than 429/502/503/504, see
// retryafter.Should) reaches the host-failover loop on the first attempt.
func errorResponse(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Header:     make(http.Header),
	}
}

func newHostFailoverClient(log *hostFailoverCaptureLogger, byHost map[string]hostRoundTripFunc, hosts ...string) *Client {
	mediaHosts := make([]MediaConnHost, len(hosts))
	for i, h := range hosts {
		mediaHosts[i] = MediaConnHost{Hostname: h}
	}
	cli := &Client{
		Log:       log,
		mediaHTTP: &http.Client{Transport: &multiHostTransport{byHost: byHost}},
	}
	cli.mediaConnCache = &MediaConn{
		Hosts:     mediaHosts,
		FetchedAt: time.Now(),
		TTL:       3600,
	}
	return cli
}

// TestDownloadHostFailover_Recovered: host 1 fails with a generic connectivity error, host 2
// succeeds. The call must succeed with host 2's data, count exactly one recovered failover,
// and never emit a Warnf -- only Debugf -- for the intermediate host-1 failure.
func TestDownloadHostFailover_Recovered(t *testing.T) {
	body := []byte("plain media bytes for the host-failover recovery test")
	log := &hostFailoverCaptureLogger{}
	cli := newHostFailoverClient(log, map[string]hostRoundTripFunc{
		"host1.example.test": func(req *http.Request) (*http.Response, error) {
			return errorResponse(http.StatusInternalServerError), nil
		},
		"host2.example.test": func(req *http.Request) (*http.Response, error) {
			return okResponse(body), nil
		},
	}, "host1.example.test", "host2.example.test")

	beforeRecovered := hostFailoverRecovered.Load()
	beforeAttempted := hostFailoverAttempted.Load()

	data, err := cli.DownloadMediaWithPath(context.Background(), "/v/t/abc", nil, nil, nil, MediaImage, "image", true)
	if err != nil {
		t.Fatalf("expected recovery on host 2, got err: %v", err)
	}
	if string(data) != string(body) {
		t.Fatalf("data mismatch: got %q want %q", data, body)
	}
	if got := hostFailoverRecovered.Load(); got != beforeRecovered+1 {
		t.Errorf("hostFailoverRecovered = %d, want %d", got, beforeRecovered+1)
	}
	if got := hostFailoverAttempted.Load(); got != beforeAttempted+1 {
		t.Errorf("hostFailoverAttempted = %d, want %d", got, beforeAttempted+1)
	}
	if n := log.warnCount(); n != 0 {
		t.Errorf("expected zero Warnf calls on a recovered failover, got %d: %v", n, log.warn)
	}
	if n := log.debugCount(); n == 0 {
		t.Error("expected at least one Debugf call for the intermediate host-1 failure")
	}
}

// TestDownloadHostFailover_Exhausted: both hosts fail. The existing loud error return from
// the last host must be unchanged, and the exhausted counter must increment.
func TestDownloadHostFailover_Exhausted(t *testing.T) {
	log := &hostFailoverCaptureLogger{}
	cli := newHostFailoverClient(log, map[string]hostRoundTripFunc{
		"host1.example.test": func(req *http.Request) (*http.Response, error) {
			return errorResponse(http.StatusInternalServerError), nil
		},
		"host2.example.test": func(req *http.Request) (*http.Response, error) {
			return errorResponse(http.StatusInternalServerError), nil
		},
	}, "host1.example.test", "host2.example.test")

	beforeExhausted := hostFailoverExhausted.Load()
	beforeAttempted := hostFailoverAttempted.Load()

	_, err := cli.DownloadMediaWithPath(context.Background(), "/v/t/abc", nil, nil, nil, MediaImage, "image", true)
	if err == nil {
		t.Fatal("expected an error after exhausting every host")
	}
	if !strings.Contains(err.Error(), "failed to download media from last host") {
		t.Errorf("unexpected error shape (terminal exhaustion must keep the existing message): %v", err)
	}
	if got := hostFailoverExhausted.Load(); got != beforeExhausted+1 {
		t.Errorf("hostFailoverExhausted = %d, want %d", got, beforeExhausted+1)
	}
	// Host 1 still counts as one intermediate attempted-and-failed-over step before host 2
	// (the last host) exhausts the list.
	if got := hostFailoverAttempted.Load(); got != beforeAttempted+1 {
		t.Errorf("hostFailoverAttempted = %d, want %d", got, beforeAttempted+1)
	}
}
