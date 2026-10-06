package whatsmeow

import (
	"context"
	"crypto/cipher"
	"errors"
	"sync"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
)

type retryContextSessions struct {
	store.NoopStore
	mu       sync.Mutex
	sessions map[string][]byte
}

func (s *retryContextSessions) IsTrustedIdentity(context.Context, string, [32]byte) (bool, error) {
	return true, nil
}
func (s *retryContextSessions) GetSession(_ context.Context, address string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.sessions[address]...), nil
}
func (s *retryContextSessions) PutSession(_ context.Context, address string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[address] = append([]byte(nil), data...)
	return nil
}

func TestRetryContextRejectsBeforePayloadLookup(t *testing.T) {
	buffer := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
	cli := phase100RetryClient(buffer)
	denied := errors.New("not admitted")
	cli.RetryContext = func(ctx context.Context, _ *events.Receipt, _ types.MessageID, _ int) (context.Context, func(error), error) {
		return ctx, nil, denied
	}
	node := &waBinary.Node{Content: []waBinary.Node{{Tag: "retry", Attrs: waBinary.Attrs{"id": "protected", "t": "1", "count": "1"}}}}
	if err := cli.handleRetryReceipt(context.Background(), &events.Receipt{}, node); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if buffer.byIDReads != 0 {
		t.Fatal("denied retry accessed private payload")
	}
}

// Exercise a real encrypted retry and physical Noise/FrameSocket write, with
// cancellation after admission but before that blocked writer returns.
func TestRetryContextJoinsPhysicalRetryWrite(t *testing.T) {
	buffer := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
	var paused *phase100RetryPausedCipher
	peer := phase100Peer(t, func(key cipher.AEAD) cipher.AEAD {
		paused = &phase100RetryPausedCipher{AEAD: key, paused: make(chan struct{}), resume: make(chan struct{})}
		return paused
	})
	cli := phase100RetryClient(buffer)
	phase100Install(cli, peer)
	sessions := &retryContextSessions{sessions: make(map[string][]byte)}
	cli.Store.Sessions, cli.Store.Identities = sessions, sessions
	cli.Store.IdentityKey = keys.NewKeyPair()
	cli.Store.RegistrationID = 7
	sender := types.NewJID("70002", types.HiddenUserServer)
	receipt := &events.Receipt{}
	receipt.Chat, receipt.Sender = sender, sender
	if err := cli.addRecentMessage(context.Background(), sender, "retry-context", phase100Payload(), nil, false); err != nil {
		t.Fatal(err)
	}
	remoteIdentity := keys.NewKeyPair()
	signed := remoteIdentity.CreateSignedPreKey(1)
	node := &waBinary.Node{Tag: "receipt", Attrs: waBinary.Attrs{"from": sender}, Content: []waBinary.Node{
		{Tag: "retry", Attrs: waBinary.Attrs{"id": "retry-context", "t": "1", "count": "1"}},
		{Tag: "registration", Content: []byte{0, 0, 0, 8}},
		{Tag: "keys", Content: []waBinary.Node{
			{Tag: "identity", Content: remoteIdentity.Pub[:]},
			{Tag: "skey", Content: []waBinary.Node{
				{Tag: "id", Content: []byte{0, 0, 1}},
				{Tag: "value", Content: signed.Pub[:]},
				{Tag: "signature", Content: signed.Signature[:]},
			}},
		}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	cli.RetryContext = func(context.Context, *events.Receipt, types.MessageID, int) (context.Context, func(error), error) {
		return ctx, func(err error) { finished <- err }, nil
	}
	done := make(chan error, 1)
	go func() { done <- cli.handleRetryReceipt(context.Background(), receipt, node) }()
	select {
	case <-paused.paused:
	case err := <-done:
		t.Fatalf("retry stopped before physical write: %v", err)
	case <-time.After(time.Second):
		t.Fatal("retry did not reach physical write")
	}
	cancel()
	select {
	case <-finished:
		t.Fatal("owner finished while physical retry write remained blocked")
	case <-time.After(20 * time.Millisecond):
	}
	close(paused.resume)
	close(peer.wire.release)
	phase100Await(t, done)
	phase100Await(t, finished)
	// A cancellation can prevent or abort the write; owner completion always
	// follows the actual write's return, regardless of its transport outcome.
	peer.finish(t, 0, 0, 0)
}
