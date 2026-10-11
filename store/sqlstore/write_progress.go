package sqlstore

import (
	"context"
	"sync/atomic"
	"time"
)

type writeProgress struct {
	since, started, lastCommit, latency atomic.Int64
	commits                             atomic.Uint64
}

func (p *writeProgress) markPending()     { p.since.CompareAndSwap(0, time.Now().UnixNano()) }
func (p *writeProgress) begin() time.Time { t := time.Now(); p.started.Store(t.UnixNano()); return t }
func (p *writeProgress) end(t time.Time, err error) {
	if err == nil {
		p.commits.Add(1)
		p.lastCommit.Store(time.Now().UnixNano())
		p.latency.Store(int64(time.Since(t)))
	}
	p.started.Store(0)
}

// WriteBackStatus includes dirty records, queued control work and active database writes.
// OldestAge is conservative while the same key keeps advancing across successful flushes.
type WriteBackStatus struct {
	MaxUtilization                       float64
	Pending, Capacity, InFlight          int64
	OldestAge, AttemptAge, CommitLatency time.Duration
	Commits                              uint64
	LastCommit                           int64
}

func (s *WriteBackStatus) add(p *writeProgress, pending, capacity int) {
	s.Pending += int64(pending)
	s.Capacity += int64(capacity)
	s.MaxUtilization = max(s.MaxUtilization, float64(pending)/float64(max(capacity, 1)))
	if since := p.since.Load(); pending > 0 && since != 0 {
		s.OldestAge = max(s.OldestAge, time.Since(time.Unix(0, since)))
	}
	if since := p.started.Load(); since != 0 {
		s.InFlight++
		s.AttemptAge = max(s.AttemptAge, time.Since(time.Unix(0, since)))
	}
	s.Commits += p.commits.Load()
	s.LastCommit = max(s.LastCommit, p.lastCommit.Load())
	if pending > 0 {
		s.CommitLatency = max(s.CommitLatency, time.Duration(p.latency.Load()))
	}
}

// WriteBackStatus snapshots existing flushers without closing their stores.
func (c *Container) WriteBackStatus() WriteBackStatus {
	var s WriteBackStatus
	c.caches.senderKeyFlushersMu.Lock()
	for _, f := range c.caches.senderKeyFlusherMap {
		s.add(&f.progress, f.DirtyCount(), f.cap)
	}
	c.caches.senderKeyFlushersMu.Unlock()
	c.caches.sessionFlushersMu.Lock()
	for _, f := range c.caches.sessionFlusherMap {
		s.add(&f.progress, f.DirtyCount()+len(f.workCh), f.cap)
		s.InFlight += f.activeWork.Load()
	}
	c.caches.sessionFlushersMu.Unlock()
	return s
}

// DrainWrites leaves workers, caches, and database connections open on a wait timeout.
// Call only after transport, application handlers and API producers have joined.
func (c *Container) DrainWrites(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		c.caches.senderKeyFlushersMu.Lock()
		for _, f := range c.caches.senderKeyFlusherMap {
			select {
			case f.flushCh <- struct{}{}:
			default:
			}
		}
		c.caches.senderKeyFlushersMu.Unlock()
		c.caches.sessionFlushersMu.Lock()
		for _, f := range c.caches.sessionFlusherMap {
			select {
			case f.flushCh <- struct{}{}:
			default:
			}
		}
		c.caches.sessionFlushersMu.Unlock()
		s := c.WriteBackStatus()
		if s.Pending == 0 && s.InFlight == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// writeRetry is owned by the serialized writer, so a burst of pressure signals
// cannot amplify a fast database failure into one SQL attempt per producer.
type writeRetry struct {
	delay time.Duration
	next  time.Time
	err   error
}

func (r *writeRetry) waiting() error {
	if time.Now().Before(r.next) {
		return r.err
	}
	return nil
}
func (r *writeRetry) record(err error) {
	if err == nil {
		*r = writeRetry{}
		return
	}
	if r.delay == 0 {
		r.delay = 100 * time.Millisecond
	} else {
		r.delay = min(r.delay*2, 5*time.Second)
	}
	r.err = err
	r.next = time.Now().Add(r.delay)
}
