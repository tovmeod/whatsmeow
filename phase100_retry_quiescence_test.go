package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	_ "unsafe" // test-only linkage to the existing constructor; no production seam

	"github.com/coder/websocket"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

//go:linkname phase100NewNoiseSocket go.mau.fi/whatsmeow/socket.newNoiseSocket
func phase100NewNoiseSocket(*socket.FrameSocket, cipher.AEAD, cipher.AEAD, socket.FrameHandler, socket.DisconnectHandler) (*socket.NoiseSocket, error)

func phase100SelectedExtra() SendRequestExtra {
	return SendRequestExtra{Timeout: time.Second, DisableAutoRetry: true}
}

type phase100RetryBuffer struct {
	store.NoopStore
	mu                sync.Mutex
	rows              map[recentMessageKey][]byte
	writes, byIDReads int
	lookupErr         error
}

func (b *phase100RetryBuffer) AddOutgoingEvent(_ context.Context, chat types.JID, id types.MessageID, format string, payload []byte) error {
	if format != "wa" {
		return errors.New("unexpected retry format")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writes++
	b.rows[recentMessageKey{chat, id}] = append([]byte(nil), payload...)
	return nil
}
func (b *phase100RetryBuffer) GetOutgoingEvent(_ context.Context, chat, alt types.JID, id types.MessageID) (string, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, to := range []types.JID{chat, alt} {
		if payload, ok := b.rows[recentMessageKey{to, id}]; ok {
			return "wa", append([]byte(nil), payload...), nil
		}
	}
	return "", nil, sql.ErrNoRows
}
func (b *phase100RetryBuffer) GetOutgoingEventByID(_ context.Context, id types.MessageID) (string, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.byIDReads++
	if b.lookupErr != nil {
		return "", nil, b.lookupErr
	}
	for key, payload := range b.rows {
		if key.ID == id {
			return "wa", append([]byte(nil), payload...), nil
		}
	}
	return "", nil, sql.ErrNoRows
}

type phase100LIDs struct {
	store.NoopStore
	pn, lid types.JID
}

func (l *phase100LIDs) GetLIDForPN(_ context.Context, pn types.JID) (types.JID, error) {
	if pn == l.pn {
		return l.lid, nil
	}
	return types.EmptyJID, nil
}
func (l *phase100LIDs) GetPNForLID(_ context.Context, lid types.JID) (types.JID, error) {
	if lid == l.lid {
		return l.pn, nil
	}
	return types.EmptyJID, nil
}

func phase100RetryClient(b *phase100RetryBuffer) *Client {
	own := types.NewJID("15550001", types.DefaultUserServer)
	cli := NewClient(&store.Device{ID: &own, EventBuffer: b, LIDs: &phase100LIDs{pn: types.NewJID("15550002", types.DefaultUserServer), lid: types.NewJID("70002", types.HiddenUserServer)}, Log: waLog.Noop}, waLog.Noop)
	cli.UseRetryMessageStore = true
	cli.lastRetryStoreClear = time.Now()
	cli.isLoggedIn.Store(true)
	return cli
}

type phase100RetryWire struct {
	io.ReadWriteCloser
	entered, release, closed chan struct{}
	once, closeOnce          sync.Once
	starts, completions      atomic.Int32
}

func (w *phase100RetryWire) Write(p []byte) (int, error) {
	w.starts.Add(1)
	w.once.Do(func() { close(w.entered) })
	select {
	case <-w.release:
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
	n, err := w.ReadWriteCloser.Write(p)
	if err == nil && n == len(p) {
		w.completions.Add(1)
	}
	return n, err
}
func (w *phase100RetryWire) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return w.ReadWriteCloser.Close()
}

type phase100RetryTransport struct {
	http.RoundTripper
	wire chan *phase100RetryWire
}

func (tr *phase100RetryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := tr.RoundTripper.RoundTrip(r)
	if err == nil && resp.StatusCode == http.StatusSwitchingProtocols {
		w := &phase100RetryWire{ReadWriteCloser: resp.Body.(io.ReadWriteCloser), entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
		resp.Body = w
		tr.wire <- w
	}
	return resp, err
}

type phase100RetryPeer struct {
	ns      *socket.NoiseSocket
	fs      *socket.FrameSocket
	wire    *phase100RetryWire
	frames  chan *waBinary.Node
	drained chan int
}

func phase100Await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("loopback fixture did not complete")
		var zero T
		return zero
	}
}
func phase100Peer(t *testing.T, decorate ...func(cipher.AEAD) cipher.AEAD) *phase100RetryPeer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	p := &phase100RetryPeer{frames: make(chan *waBinary.Node, 8), drained: make(chan int, 1)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := websocket.Accept(w, r, nil)
		if err != nil {
			p.drained <- -1
			return
		}
		defer peer.CloseNow()
		count := 0
		for {
			kind, data, err := peer.Read(ctx)
			if err != nil {
				p.drained <- count
				return
			}
			if kind != websocket.MessageBinary || len(data) < 3 || int(data[0])<<16|int(data[1])<<8|int(data[2]) != len(data)-3 {
				p.drained <- -1
				return
			}
			iv := make([]byte, 12)
			binary.BigEndian.PutUint32(iv[8:], uint32(count))
			plain, err := key.Open(nil, iv, data[3:], nil)
			if err != nil {
				p.drained <- -1
				return
			}
			unpacked, err := waBinary.Unpack(plain)
			if err != nil {
				p.drained <- -1
				return
			}
			node, err := waBinary.Unmarshal(unpacked)
			if err != nil {
				p.drained <- -1
				return
			}
			count++
			p.frames <- node
		}
	}))
	tr := &phase100RetryTransport{RoundTripper: server.Client().Transport, wire: make(chan *phase100RetryWire, 1)}
	p.fs = socket.NewFrameSocket(waLog.Noop, &http.Client{Transport: tr})
	p.fs.URL, p.fs.HTTPHeaders, p.fs.Header = "ws"+strings.TrimPrefix(server.URL, "http"), http.Header{}, nil
	if err := p.fs.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	p.wire = phase100Await(t, tr.wire)
	writeKey := key
	if len(decorate) > 0 {
		writeKey = decorate[0](key)
	}
	p.ns, err = phase100NewNoiseSocket(p.fs, writeKey, key, func(context.Context, []byte) {}, func(context.Context, *socket.NoiseSocket, bool) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.ns.Stop(false, true); p.fs.Close(0); cancel(); server.Close() })
	return p
}
func (p *phase100RetryPeer) finish(t *testing.T, starts, completions, frames int) {
	t.Helper()
	p.fs.Close(0)
	got := phase100Await(t, p.drained)
	if p.wire.starts.Load() != int32(starts) || p.wire.completions.Load() != int32(completions) || got != frames {
		t.Fatalf("physical starts/completions/decoded peer frames=%d/%d/%d, want %d/%d/%d", p.wire.starts.Load(), p.wire.completions.Load(), got, starts, completions, frames)
	}
	t.Logf("physical_write_starts=%d physical_write_completions=%d decoded_peer_frames=%d", starts, completions, frames)
}
func phase100Install(cli *Client, p *phase100RetryPeer) {
	cli.socketLock.Lock()
	cli.socket = p.ns
	cli.socketLock.Unlock()
}

type phase100SendResult struct {
	response SendResponse
	err      error
}

var phase100Newsletter = types.NewJID("90001", types.NewsletterServer)

func phase100Start(cli *Client, ctx context.Context, extra SendRequestExtra, msg *waE2E.Message) <-chan phase100SendResult {
	ch := make(chan phase100SendResult, 1)
	go func() {
		response, err := cli.SendMessage(ctx, phase100Newsletter, msg, extra)
		ch <- phase100SendResult{response, err}
	}()
	return ch
}
func phase100Payload() *waE2E.Message {
	return &waE2E.Message{Conversation: proto.String("synthetic private payload")}
}
func phase100PendingID(t *testing.T, cli *Client) types.MessageID {
	t.Helper()
	cli.responseWaitersLock.Lock()
	defer cli.responseWaitersLock.Unlock()
	if len(cli.responseWaiters) != 1 {
		t.Fatalf("pending responses=%d", len(cli.responseWaiters))
	}
	for id := range cli.responseWaiters {
		return id
	}
	return ""
}
func phase100ACK(t *testing.T, cli *Client, id string) {
	t.Helper()
	if !cli.receiveResponse(context.Background(), &waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": id, "t": "1"}}) {
		t.Fatal("real response waiter not reached")
	}
}

// Deterministic random bytes arrange a real generated-ID collision without
// accepting a caller ID or adding a production generator hook. No parallel use.
type phase100ZeroRandom struct{}

func (phase100ZeroRandom) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func phase100CollisionIDs(cli *Client) []string {
	ids := make([]string, 0, 21)
	for offset := int64(-10); offset <= 10; offset++ {
		data := make([]byte, 8)
		binary.BigEndian.PutUint64(data, uint64(time.Now().Unix()+offset))
		data = append(data, []byte(cli.getOwnID().User+"@c.us")...)
		data = append(data, make([]byte, 16)...)
		hash := sha256.Sum256(data)
		ids = append(ids, WebMessageIDPrefix+strings.ToUpper(hex.EncodeToString(hash[:9])))
	}
	return ids
}

type phase100RetryDelayedCancel struct {
	context.Context
	done, callbacks chan struct{}
	cancelled       atomic.Bool
}

func (c *phase100RetryDelayedCancel) Done() <-chan struct{} { return c.done }
func (c *phase100RetryDelayedCancel) Err() error {
	if c.cancelled.Load() {
		return context.Canceled
	}
	return nil
}
func (c *phase100RetryDelayedCancel) AfterFunc(fn func()) func() bool {
	var stopped atomic.Bool
	go func() {
		<-c.done
		<-c.callbacks
		if !stopped.Load() {
			fn()
		}
	}()
	return func() bool { return !stopped.Swap(true) }
}

type phase100RetryPausedCipher struct {
	cipher.AEAD
	paused, resume chan struct{}
}

func (k *phase100RetryPausedCipher) Seal(dst, nonce, plaintext, additional []byte) []byte {
	close(k.paused)
	<-k.resume
	return k.AEAD.Seal(dst, nonce, plaintext, additional)
}

func TestPhase100NoAutoRetry(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "ordinary"
		if selected {
			name = "selected"
		}
		t.Run(name+"_prepared_receipt_sources", func(t *testing.T) {
			b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
			cli, p := phase100RetryClient(b), phase100Peer(t)
			phase100Install(cli, p)
			var fallback, preRetry atomic.Int32
			cli.GetMessageForRetry = func(types.JID, types.JID, types.MessageID) *waE2E.Message { fallback.Add(1); return phase100Payload() }
			cli.PreRetryCallback = func(*events.Receipt, types.MessageID, int, *waE2E.Message) bool { preRetry.Add(1); return false }
			extra := SendRequestExtra{ID: "ordinary-custom-id", Timeout: time.Second}
			if selected {
				extra = phase100SelectedExtra()
			}
			done := phase100Start(cli, context.Background(), extra, phase100Payload())
			phase100Await(t, p.wire.entered)
			id := phase100PendingID(t, cli)
			if p.wire.starts.Load() != 1 || p.wire.completions.Load() != 0 {
				t.Fatal("prepared/in-flight observations collapsed")
			}
			// Inspect while the original physical Write remains blocked.
			for _, restart := range []bool{false, true} {
				lookup := cli
				if restart {
					lookup = phase100RetryClient(b)
					lookup.GetMessageForRetry = cli.GetMessageForRetry
					lookup.PreRetryCallback = cli.PreRetryCallback
				}
				lids := lookup.Store.LIDs.(*phase100LIDs)
				for _, chat := range []types.JID{phase100Newsletter, lids.pn, lids.lid, lookup.getOwnID()} {
					receipt := &events.Receipt{}
					receipt.Chat, receipt.Sender, receipt.IsFromMe = chat, lids.pn, chat == lookup.getOwnID()
					msg, err := lookup.getMessageForRetry(context.Background(), receipt, id, time.Time{})
					wantPayload := !selected && (chat == phase100Newsletter || chat == lookup.getOwnID())
					if wantPayload {
						if err != nil || msg == nil || !proto.Equal(msg.wa, phase100Payload()) {
							t.Errorf("ordinary retry source did not preserve payload: restart=%v chat=%s err=%v", restart, chat, err)
						}
					} else if msg != nil {
						t.Errorf("protected payload available before first completed Write: restart=%v chat=%s", restart, chat)
					}
					node := &waBinary.Node{Tag: "receipt", Attrs: waBinary.Attrs{"from": receipt.Sender}, Content: []waBinary.Node{{Tag: "retry", Attrs: waBinary.Attrs{"id": id, "t": "1", "count": "1"}}}}
					handlerErr := lookup.handleRetryReceipt(context.Background(), receipt, node)
					if !wantPayload && handlerErr == nil {
						t.Errorf("absent payload receipt unexpectedly accepted: %s", chat)
					}
					if selected && len(lookup.incomingRetryRequestCounter) != 0 {
						t.Error("selected receipt reached retry/encryption admission")
					}
				}
			}
			cli.recentMessagesLock.RLock()
			cacheWrites := len(cli.recentMessagesMap)
			cli.recentMessagesLock.RUnlock()
			b.mu.Lock()
			storeWrites := b.writes
			b.mu.Unlock()
			want := 1
			if selected {
				want = 0
			}
			if cacheWrites != want || storeWrites != want {
				t.Errorf("selected retry preparation writes: cache=%d store=%d want=%d", cacheWrites, storeWrites, want)
			}
			if fallback.Load() != 0 || selected && preRetry.Load() != 0 {
				t.Errorf("fallback/pre-retry reached: %d/%d", fallback.Load(), preRetry.Load())
			}
			if !selected && preRetry.Load() != 4 {
				t.Errorf("ordinary receipt recovery control calls=%d want4", preRetry.Load())
			}
			close(p.wire.release)
			node := phase100Await(t, p.frames)
			if node.Tag != "message" || node.AttrGetter().String("id") != id {
				t.Fatal("decoded original message/ID mismatch")
			}
			phase100ACK(t, cli, id)
			result := phase100Await(t, done)
			if result.err != nil {
				t.Fatal(result.err)
			}
			p.finish(t, 1, 1, 1)
			t.Logf("retry_cache_writes=%d retry_store_writes=%d fallback_calls=%d pre_retry_calls=%d", cacheWrites, storeWrites, fallback.Load(), preRetry.Load())
		})
		t.Run(name+"_replacement_socket", func(t *testing.T) {
			b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
			cli, original, replacement := phase100RetryClient(b), phase100Peer(t), phase100Peer(t)
			phase100Install(cli, original)
			close(original.wire.release)
			close(replacement.wire.release)
			extra := SendRequestExtra{Timeout: time.Second}
			if selected {
				extra = phase100SelectedExtra()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := phase100Start(cli, ctx, extra, phase100Payload())
			node := phase100Await(t, original.frames)
			id := node.AttrGetter().String("id")
			phase100Install(cli, replacement)
			cli.clearResponseWaiters(xmlStreamEndNode)
			if selected {
				// On the old implementation the peer receives a retry; acknowledge it
				// so RED reports a behavior assertion, not a fixture timeout.
				select {
				case retry := <-replacement.frames:
					phase100ACK(t, cli, retry.AttrGetter().String("id"))
				case result := <-done:
					var disconnected *DisconnectedError
					if !errors.As(result.err, &disconnected) {
						t.Errorf("selected disconnect did not preserve uncertainty: %v", result.err)
					}
					original.finish(t, 1, 1, 1)
					replacement.finish(t, 0, 0, 0)
					return
				case <-ctx.Done():
					t.Fatal("reconnect fixture timed out")
				}
			} else {
				retry := phase100Await(t, replacement.frames)
				if retry.AttrGetter().String("id") != id {
					t.Fatal("ordinary retry changed ID")
				}
				phase100ACK(t, cli, id)
			}
			result := phase100Await(t, done)
			if selected {
				t.Errorf("selected replacement socket emitted automatic retry: result=%v", result.err)
			} else if result.err != nil {
				t.Fatal(result.err)
			}
			original.finish(t, 1, 1, 1)
			want := 1
			if selected {
				want = 0
			}
			replacement.finish(t, want, want, want)
		})
	}
	for _, name := range []string{"caller_id", "peer", "edit_id", "revoke_id", "store_disabled", "store_missing", "lookup_failure", "durable_collision", "recent_collision"} {
		t.Run("reject_"+name+"_before_write", func(t *testing.T) {
			b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
			cli, p := phase100RetryClient(b), phase100Peer(t)
			phase100Install(cli, p)
			extra, msg := phase100SelectedExtra(), phase100Payload()
			switch name {
			case "caller_id":
				extra.ID = "old-id"
			case "peer":
				extra.Peer = true
			case "edit_id":
				msg = &waE2E.Message{EditedMessage: &waE2E.FutureProofMessage{Message: &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{Key: &waCommon.MessageKey{ID: proto.String("old-id")}, EditedMessage: phase100Payload()}}}}
			case "revoke_id":
				msg = &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{Type: waE2E.ProtocolMessage_REVOKE.Enum(), Key: &waCommon.MessageKey{ID: proto.String("old-id")}}}
			case "store_disabled":
				cli.UseRetryMessageStore = false
			case "store_missing":
				cli.Store.EventBuffer = nil
			case "lookup_failure":
				b.lookupErr = errors.New("owned lookup unavailable")
			case "durable_collision", "recent_collision":
				originalRandom := rand.Reader
				rand.Reader = phase100ZeroRandom{}
				defer func() { rand.Reader = originalRandom }()
				oldBytes, _ := proto.Marshal(&waE2E.Message{Conversation: proto.String("old ordinary payload")})
				for _, id := range phase100CollisionIDs(cli) {
					oldChat := cli.getOwnID()
					if name == "durable_collision" {
						b.rows[recentMessageKey{oldChat, id}] = oldBytes
					} else {
						cli.recentMessagesMap[recentMessageKey{oldChat, id}] = RecentMessage{wa: &waE2E.Message{Conversation: proto.String("old ordinary payload")}}
					}
				}
			}
			// Release the physical gate even in RED; listener success is observed
			// separately, and rejection must still have zero actual starts.
			close(p.wire.release)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			response, err := cli.SendMessage(ctx, phase100Newsletter, msg, extra)
			if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrMessageTimedOut) {
				t.Errorf("invalid no-auto-retry input was not rejected before Write: %v", err)
			}
			if name == "durable_collision" || name == "recent_collision" {
				old := cli.getRecentMessage(cli.getOwnID(), response.ID)
				if name == "durable_collision" {
					_, payload, e := b.GetOutgoingEventByID(context.Background(), response.ID)
					if e != nil || !strings.Contains(string(payload), "old ordinary payload") {
						t.Error("durable old ordinary payload removed/replaced")
					}
				} else if old.IsEmpty() || old.wa.GetConversation() != "old ordinary payload" {
					t.Error("recent old ordinary payload removed/replaced")
				}
			}
			p.finish(t, 0, 0, 0)
		})
	}
	t.Run("selected_pre_cancel", func(t *testing.T) {
		b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
		cli, p := phase100RetryClient(b), phase100Peer(t)
		phase100Install(cli, p)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := cli.SendMessage(ctx, phase100Newsletter, phase100Payload(), phase100SelectedExtra())
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		p.finish(t, 0, 0, 0)
		if b.writes != 0 || len(cli.recentMessagesMap) != 0 {
			t.Error("pre-cancelled selected send retained retry payload")
		}
	})
	t.Run("selected_close_during_write", func(t *testing.T) {
		b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
		cli, p := phase100RetryClient(b), phase100Peer(t)
		phase100Install(cli, p)
		done := phase100Start(cli, context.Background(), phase100SelectedExtra(), phase100Payload())
		phase100Await(t, p.wire.entered)
		if err := p.wire.Close(); err != nil {
			t.Fatal(err)
		}
		result := phase100Await(t, done)
		if result.err == nil || p.ns.IsConnected() {
			t.Fatal("close error must remain uncertain and retire exact socket")
		}
		p.finish(t, 1, 0, 0)
		if b.writes != 0 || len(cli.recentMessagesMap) != 0 {
			t.Error("closed selected send retained retry payload")
		}
	})
	t.Run("selected_disconnect_while_write_inflight", func(t *testing.T) {
		b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
		cli, original, replacement := phase100RetryClient(b), phase100Peer(t), phase100Peer(t)
		phase100Install(cli, original)
		close(replacement.wire.release)
		done := phase100Start(cli, context.Background(), phase100SelectedExtra(), phase100Payload())
		phase100Await(t, original.wire.entered)
		phase100Install(cli, replacement)
		cli.clearResponseWaiters(xmlStreamEndNode)
		if original.wire.completions.Load() != 0 {
			t.Fatal("original Write unexpectedly completed")
		}
		close(original.wire.release)
		phase100Await(t, original.frames)
		result := phase100Await(t, done)
		var disconnected *DisconnectedError
		if !errors.As(result.err, &disconnected) {
			t.Fatalf("in-flight disconnect lost uncertainty: %v", result.err)
		}
		original.finish(t, 1, 1, 1)
		replacement.finish(t, 0, 0, 0)
	})
	t.Run("selected_delayed_callback_positive_write", func(t *testing.T) {
		b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
		cli, p := phase100RetryClient(b), phase100Peer(t)
		phase100Install(cli, p)
		ctx := &phase100RetryDelayedCancel{Context: context.Background(), done: make(chan struct{}), callbacks: make(chan struct{})}
		defer close(ctx.callbacks)
		done := phase100Start(cli, ctx, phase100SelectedExtra(), phase100Payload())
		phase100Await(t, p.wire.entered)
		ctx.cancelled.Store(true)
		close(ctx.done)
		select {
		case result := <-done:
			t.Fatalf("operation returned before original Write: %v", result.err)
		case <-time.After(20 * time.Millisecond):
		}
		close(p.wire.release)
		phase100Await(t, p.frames)
		result := phase100Await(t, done)
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("completed Write plus canceled ACK wait must remain uncertain: %v", result.err)
		}
		p.finish(t, 1, 1, 1)
		if b.writes != 0 || len(cli.recentMessagesMap) != 0 {
			t.Fatal("delayed callback selected payload retained")
		}
	})
	t.Run("selected_cancel_after_noise_precheck", func(t *testing.T) {
		b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
		paused := &phase100RetryPausedCipher{paused: make(chan struct{}), resume: make(chan struct{})}
		p := phase100Peer(t, func(key cipher.AEAD) cipher.AEAD { paused.AEAD = key; return paused })
		cli := phase100RetryClient(b)
		phase100Install(cli, p)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := phase100Start(cli, ctx, phase100SelectedExtra(), phase100Payload())
		phase100Await(t, paused.paused)
		cancel()
		close(paused.resume)
		result := phase100Await(t, done)
		if !errors.Is(result.err, context.Canceled) || p.ns.IsConnected() {
			t.Fatalf("precheck race did not retire exact socket: %v", result.err)
		}
		p.finish(t, 0, 0, 0)
		if b.writes != 0 || len(cli.recentMessagesMap) != 0 {
			t.Fatal("precheck selected payload retained")
		}
	})
	t.Run("ordinary_alternate_sources_positive", func(t *testing.T) {
		b := &phase100RetryBuffer{rows: make(map[recentMessageKey][]byte)}
		cli := phase100RetryClient(b)
		lids := cli.Store.LIDs.(*phase100LIDs)
		for _, original := range []types.JID{lids.pn, lids.lid} {
			id := "old-ordinary-" + original.Server
			if err := cli.addRecentMessage(context.Background(), original, id, phase100Payload(), nil, false); err != nil {
				t.Fatal(err)
			}
			for _, lookup := range []*Client{cli, phase100RetryClient(b)} {
				for _, chat := range []types.JID{lids.pn, lids.lid, cli.getOwnID()} {
					receipt := &events.Receipt{}
					receipt.Chat, receipt.Sender = chat, lids.pn
					msg, err := lookup.getMessageForRetry(context.Background(), receipt, id, time.Time{})
					if err != nil || msg == nil || !proto.Equal(msg.wa, phase100Payload()) {
						t.Fatalf("ordinary exact/alternate/durable/self-ID recovery failed: chat=%s err=%v", chat, err)
					}
				}
			}
		}
	})
}
