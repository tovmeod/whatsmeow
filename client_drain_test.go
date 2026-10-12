package whatsmeow

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestDisconnectDrainJoinsActiveAndFinalQueuedHandoff(t *testing.T) {
	cli := NewClient(&store.Device{}, waLog.Noop)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var handled atomic.Int64
	cli.nodeHandlers = map[string]nodeHandler{
		"message": func(ctx context.Context, _ *waBinary.Node) {
			if handled.Add(1) == 1 {
				close(started)
				<-release
			}
			if ctx.Err() != nil {
				t.Error("accepted node inherited canceled connection context")
			}
		},
	}
	queue := make(chan *waBinary.Node, 1)
	done, intakeDone := make(chan struct{}), make(chan struct{})
	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli.handlerQueueWait = done
	go cli.handlerQueueLoop(context.Background(), connCtx, queue, done, intakeDone)
	cli.nodeQueued.Add(1)
	queue <- &waBinary.Node{Tag: "message"}
	<-started
	// The last accepted node is blocked behind the full queue at cancellation.
	cli.nodeQueued.Add(2)
	queue <- &waBinary.Node{Tag: "message"}
	go func() { queue <- &waBinary.Node{Tag: "message"}; close(intakeDone) }()
	cancel()
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if err := cli.DisconnectAndDrain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain error=%v", err)
	}
	if pending, _, _ := cli.HandlerStatus(); pending != 3 {
		t.Fatalf("outstanding accepted nodes=%d, want 3", pending)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accepted handoff failed to drain")
	}
	if handled.Load() != 3 {
		t.Fatalf("handled=%d, want all accepted nodes", handled.Load())
	}
	if pending, active, _ := cli.HandlerStatus(); pending != 0 || active != 0 {
		t.Fatalf("undrained status=%d/%d", pending, active)
	}
}

func TestDisconnectDrainJoinsDetachedProtocolChild(t *testing.T) {
	cli := NewClient(&store.Device{}, waLog.Noop)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var stored atomic.Bool
	cli.runAsyncProtocol(func() { <-release; stored.Store(true) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := cli.DisconnectAndDrain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain error=%v", err)
	}
	if stored.Load() {
		t.Fatal("child finished before controlled database recovery")
	}
	unblock()
	if err := cli.DisconnectAndDrain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !stored.Load() {
		t.Fatal("drain returned before detached protocol child committed")
	}
}
