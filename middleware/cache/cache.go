// Package cache is a dnsserver.Handler middleware that answers repeated
// queries from an in-memory, TTL-aware, size-bounded cache instead of
// forwarding every one to the wrapped Handler.
package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
)

const (
	defaultMaxEntries = 10000
	// negativeCacheFallbackTTL is used for NXDOMAIN responses that (unusually)
	// carried no SOA record to derive a proper negative TTL from (RFC 2308).
	negativeCacheFallbackTTL = 60
)

type key struct {
	name  string
	qtype dnsmsg.RRType
}

type entry struct {
	rcode       dnsmsg.RCode
	answers     []dnsmsg.RR
	authorities []dnsmsg.RR
	expiry      time.Time
	elem        *list.Element
}

// store is a TTL-aware, size-bounded (LRU-evicted) cache of DNS responses.
type store struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[key]*entry
	order      *list.List // front = most recently used
}

func newStore(maxEntries int) *store {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	return &store{
		maxEntries: maxEntries,
		entries:    make(map[key]*entry),
		order:      list.New(),
	}
}

// lookup returns a cached response for (name, qtype) with each RR's TTL
// reduced by the time elapsed since it was stored. ok is false on a miss or
// if the entry has fully expired (in which case it's evicted here).
func (s *store) lookup(name string, qtype dnsmsg.RRType) (rcode dnsmsg.RCode, answers, authorities []dnsmsg.RR, ok bool) {
	k := normalizeKey(name, qtype)

	s.mu.Lock()
	defer s.mu.Unlock()

	e, found := s.entries[k]
	if !found {
		return 0, nil, nil, false
	}
	remaining := time.Until(e.expiry)
	if remaining <= 0 {
		s.order.Remove(e.elem)
		delete(s.entries, k)
		return 0, nil, nil, false
	}
	s.order.MoveToFront(e.elem)

	ttl := uint32(remaining.Seconds())
	if ttl == 0 {
		ttl = 1 // round up: still valid, don't advertise a zero/expired TTL
	}
	return e.rcode, withTTL(e.answers, ttl), withTTL(e.authorities, ttl), true
}

// put caches a response. Positive responses use the smallest TTL among
// their answer RRs; NXDOMAIN responses use the negative TTL derived from
// the SOA record in authorities (RFC 2308), or a small fallback if there
// wasn't one. Anything else (SERVFAIL, NODATA, ...) is not cached.
func (s *store) put(name string, qtype dnsmsg.RRType, rcode dnsmsg.RCode, answers, authorities []dnsmsg.RR) {
	var ttl uint32
	switch {
	case rcode == dnsmsg.RCodeNameError:
		ttl = negativeTTLFromSOA(authorities, negativeCacheFallbackTTL)
	case rcode == dnsmsg.RCodeSuccess && len(answers) > 0:
		ttl = minTTL(answers)
	default:
		return
	}
	if ttl == 0 {
		return
	}

	k := normalizeKey(name, qtype)

	s.mu.Lock()
	defer s.mu.Unlock()

	if old, found := s.entries[k]; found {
		s.order.Remove(old.elem)
		delete(s.entries, k)
	}

	e := &entry{
		rcode:       rcode,
		answers:     answers,
		authorities: authorities,
		expiry:      time.Now().Add(time.Duration(ttl) * time.Second),
	}
	e.elem = s.order.PushFront(k)
	s.entries[k] = e

	for len(s.entries) > s.maxEntries {
		oldest := s.order.Back()
		if oldest == nil {
			break
		}
		s.order.Remove(oldest)
		delete(s.entries, oldest.Value.(key))
	}
}

func normalizeKey(name string, qtype dnsmsg.RRType) key {
	return key{name: strings.ToLower(strings.TrimSuffix(name, ".")), qtype: qtype}
}

func withTTL(rrs []dnsmsg.RR, ttl uint32) []dnsmsg.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dnsmsg.RR, len(rrs))
	for i, rr := range rrs {
		out[i] = rr
		out[i].TTL = ttl
	}
	return out
}

func minTTL(rrs []dnsmsg.RR) uint32 {
	m := rrs[0].TTL
	for _, rr := range rrs[1:] {
		if rr.TTL < m {
			m = rr.TTL
		}
	}
	return m
}

func negativeTTLFromSOA(authorities []dnsmsg.RR, fallback uint32) uint32 {
	for _, rr := range authorities {
		if rr.Type == dnsmsg.TypeSOA && rr.SOA != nil {
			ttl := rr.TTL
			if rr.SOA.Minimum < ttl {
				ttl = rr.SOA.Minimum
			}
			return ttl
		}
	}
	return fallback
}

// handler serves cached answers when available and otherwise forwards to
// next, caching whatever next answers.
type handler struct {
	next  dnsserver.Handler
	store *store
}

// Wrap returns a dnsserver.Handler that caches next's answers and serves
// repeated queries from the cache within their TTL. maxEntries <= 0 uses a
// built-in default.
func Wrap(next dnsserver.Handler, maxEntries int) dnsserver.Handler {
	return &handler{next: next, store: newStore(maxEntries)}
}

func (h *handler) ServeDNS(w dnsserver.ResponseWriter, req *dnsmsg.Message) {
	if len(req.Questions) != 1 {
		h.next.ServeDNS(w, req)
		return
	}
	q := req.Questions[0]

	if rcode, answers, authorities, ok := h.store.lookup(q.Name, q.Type); ok {
		w.WriteMsg(&dnsmsg.Message{
			Header: dnsmsg.Header{
				ID:    req.Header.ID,
				QR:    true,
				RD:    req.Header.RD,
				RA:    true,
				RCode: rcode,
			},
			Questions:   req.Questions,
			Answers:     answers,
			Authorities: authorities,
		})
		return
	}

	rec := &recordingWriter{ResponseWriter: w}
	h.next.ServeDNS(rec, req)
	if rec.msg != nil {
		h.store.put(q.Name, q.Type, rec.msg.Header.RCode, rec.msg.Answers, rec.msg.Authorities)
	}
}

// recordingWriter captures the message a wrapped Handler writes so the
// cache can inspect and store it, while still forwarding it to the real
// client.
type recordingWriter struct {
	dnsserver.ResponseWriter
	msg *dnsmsg.Message
}

func (w *recordingWriter) WriteMsg(msg *dnsmsg.Message) error {
	w.msg = msg
	return w.ResponseWriter.WriteMsg(msg)
}
