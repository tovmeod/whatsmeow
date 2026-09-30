package whatsmeow

import (
	"os"
	"strings"
	"testing"
)

// Regression guard: a receiver-side proactive pairwise re-establishment on inbound
// decrypt failure (establishSessionWithSender-style fetch-prekeys + ProcessBundle)
// must NOT exist. It is non-conformant (WA Web is retry-receipt-only on inbound
// failure — re-establishment is the sender's job) and a functional no-op that only
// burns the peer's one-time prekeys and bloats our pairwise session via ProcessBundle
// archiving (the slow-encrypt root cause). See wa_protocol
// docs/spec/inbound-decrypt-failure-response.md. The conformant sender-side recreate
// (retry.go shouldRecreateSession, reacting to an incoming retry request) is fine.
func TestNoReceiverProactiveSessionReestablishment(t *testing.T) {
	src, err := os.ReadFile("message.go")
	if err != nil {
		t.Fatalf("read message.go: %v", err)
	}
	if strings.Contains(string(src), "establishSessionWithSender") &&
		strings.Contains(string(src), "func (cli *Client) establishSessionWithSender") {
		t.Fatal("establishSessionWithSender reintroduced in message.go — receiver-side " +
			"proactive re-establishment on inbound decrypt failure is non-conformant and " +
			"bloats pairwise sessions; respond to inbound failures with a retry receipt only")
	}
}
