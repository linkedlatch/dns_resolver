// Package singleflight is a dnsserver.Handler middleware that collapses
// identical queries arriving at the same time into one.
//
// It sits between the cache and whatever does the work: the cache turns
// away repeats of a question it has already answered, but a burst of
// clients asking the same new question all miss together, and each miss
// walks the whole delegation chain. The popular name whose entry has just
// expired is exactly when that happens.
package singleflight

import (
	"context"
	"strings"
	"sync"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
)

type key struct {
	name  string
	qtype dnsmsg.RRType
}

// call is one query in progress that later arrivals wait on.
type call struct {
	done chan struct{}
	msg  *dnsmsg.Message // the answer, valid once done is closed
}

type handler struct {
	next dnsserver.Handler

	mu       sync.Mutex
	inFlight map[key]*call
}

// Wrap returns a Handler that runs one query at a time per distinct
// question, giving every waiter the same answer.
func Wrap(next dnsserver.Handler) dnsserver.Handler {
	return &handler{next: next, inFlight: make(map[key]*call)}
}

func (h *handler) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, req *dnsmsg.Message) {
	if len(req.Questions) != 1 {
		h.next.ServeDNS(ctx, w, req)
		return
	}
	q := req.Questions[0]
	k := key{name: strings.ToLower(strings.TrimSuffix(q.Name, ".")), qtype: q.Type}

	h.mu.Lock()
	if c, found := h.inFlight[k]; found {
		h.mu.Unlock()
		h.waitFor(ctx, c, w, req)
		return
	}
	c := &call{done: make(chan struct{})}
	h.inFlight[k] = c
	h.mu.Unlock()

	rec := &recordingWriter{ResponseWriter: w}
	// The leader answers its own client directly; the waiters copy what it
	// produced. Unregistering before waking them keeps a query that arrives
	// after the answer from joining a call that is already over.
	func() {
		defer func() {
			h.mu.Lock()
			delete(h.inFlight, k)
			h.mu.Unlock()
			c.msg = rec.msg
			close(c.done)
		}()
		h.next.ServeDNS(ctx, rec, req)
	}()
}

// waitFor blocks until the query in progress finishes, then answers this
// client with a copy of its result.
func (h *handler) waitFor(ctx context.Context, c *call, w dnsserver.ResponseWriter, req *dnsmsg.Message) {
	select {
	case <-c.done:
	case <-ctx.Done():
		return // this client gave up or the server is shutting down
	}
	if c.msg == nil {
		return // the query produced no response; nothing to share
	}

	// Copy: the ID and question are this client's, and the records must not
	// be the same memory every waiter is handed.
	out := *c.msg
	out.Header.ID = req.Header.ID
	out.Header.RD = req.Header.RD
	out.Questions = req.Questions
	out.Answers = dnsmsg.CloneRRs(c.msg.Answers)
	out.Authorities = dnsmsg.CloneRRs(c.msg.Authorities)
	out.Additionals = dnsmsg.CloneRRs(c.msg.Additionals)
	w.WriteMsg(&out)
}

// recordingWriter captures what the leader answered so the waiters can be
// given the same thing, while still forwarding it to the leader's client.
type recordingWriter struct {
	dnsserver.ResponseWriter
	msg *dnsmsg.Message
}

func (w *recordingWriter) WriteMsg(msg *dnsmsg.Message) error {
	w.msg = msg
	return w.ResponseWriter.WriteMsg(msg)
}
