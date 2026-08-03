// Package ratelimit is a dnsserver.Handler middleware that caps how many
// queries one client address may have answered per second.
//
// It complements access control: even an allowed client can drive far more
// resolution than its share, whether by accident or as a way to exhaust the
// server for everyone else.
package ratelimit

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
)

const (
	defaultRate  = 50  // queries per second, per client address
	defaultBurst = 100 // how far a client may run ahead of that rate
	// maxClients bounds the table so that traffic from many spoofed or
	// short-lived addresses cannot grow it without limit; the least
	// recently seen entries are dropped once it is full.
	maxClients = 10000
)

type bucket struct {
	tokens float64
	seen   time.Time
}

type handler struct {
	next  dnsserver.Handler
	rate  float64
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	clients map[netip.Addr]*bucket
}

// Wrap returns a Handler that limits each client address to rate queries
// per second, allowing bursts of up to burst. Zero uses the defaults.
func Wrap(next dnsserver.Handler, rate, burst float64) dnsserver.Handler {
	if rate <= 0 {
		rate = defaultRate
	}
	if burst <= 0 {
		burst = defaultBurst
	}
	return &handler{
		next:    next,
		rate:    rate,
		burst:   burst,
		now:     time.Now,
		clients: make(map[netip.Addr]*bucket),
	}
}

func (h *handler) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, req *dnsmsg.Message) {
	ip, ok := addrIP(w.RemoteAddr())
	if ok && !h.allow(ip) {
		// Dropped, not refused. A source address in a UDP query is
		// unverified, so answering an over-limit client would let an
		// attacker use those replies against whoever they claimed to be.
		return
	}
	h.next.ServeDNS(ctx, w, req)
}

// allow takes a token for ip, refilling the client's bucket for the time
// that has passed since it was last seen.
func (h *handler) allow(ip netip.Addr) bool {
	now := h.now()

	h.mu.Lock()
	defer h.mu.Unlock()

	b, found := h.clients[ip]
	if !found {
		h.evictIfFull(now)
		h.clients[ip] = &bucket{tokens: h.burst - 1, seen: now}
		return true
	}

	b.tokens = min(b.tokens+now.Sub(b.seen).Seconds()*h.rate, h.burst)
	b.seen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictIfFull drops the least recently seen client when the table is full.
// A full scan is affordable because it only runs on that boundary, and it
// keeps this from needing a second index just for eviction order.
func (h *handler) evictIfFull(now time.Time) {
	if len(h.clients) < maxClients {
		return
	}
	var oldest netip.Addr
	oldestSeen := now
	for ip, b := range h.clients {
		if !b.seen.After(oldestSeen) {
			oldest, oldestSeen = ip, b.seen
		}
	}
	delete(h.clients, oldest)
}

func addrIP(addr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}
