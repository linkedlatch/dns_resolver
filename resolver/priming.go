package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"dns_resolver/dnsmsg"
)

// primeInterval is how long a priming failure is left alone before trying
// again. The hints still work in the meantime, so there is no hurry.
const primeInterval = 5 * time.Minute

// primeRootServers replaces the built-in hints with the set the root zone
// itself publishes (RFC 8109).
//
// The hints in the source file are a bootstrap, not a source of truth: they
// are only as current as the last time someone edited them, and root server
// addresses do change. Asking the root for its own NS records - and for the
// addresses of those names, which arrive in the same response - gets the
// live set, with a TTL saying how long it is good for.
func (r *Resolver) primeRootServers(ctx context.Context) {
	// Decide whether to prime, and pick who to ask, under the lock; then
	// let it go. The query itself must not hold the lock: it is a network
	// round trip, and every other resolution needs to read the root set
	// while it is in flight.
	r.primeMu.Lock()
	if r.primedUntil.After(time.Now()) {
		r.primeMu.Unlock()
		return
	}
	// Set this first: a priming attempt that fails should not be retried on
	// every single query.
	r.primedUntil = time.Now().Add(primeInterval)
	servers := r.primed
	r.primeMu.Unlock()

	if len(servers) == 0 {
		servers = RootServers
	}

	resp, _, err := r.queryServers(ctx, servers, ".", dnsmsg.TypeNS)
	if err != nil {
		return // the hints are still there; try again later
	}

	names := make(map[string]bool)
	ttl := uint32(0)
	for _, rr := range resp.Answers {
		if rr.Type != dnsmsg.TypeNS || rr.Class != dnsmsg.ClassIN || !equalName(rr.Name, ".") {
			continue
		}
		names[normalizeName(rr.NS)] = true
		if ttl == 0 || rr.TTL < ttl {
			ttl = rr.TTL
		}
	}
	if len(names) == 0 {
		return
	}

	var addrs []net.IP
	for _, rr := range resp.Additionals {
		if !names[normalizeName(rr.Name)] || rr.Class != dnsmsg.ClassIN {
			continue
		}
		switch {
		case rr.Type == dnsmsg.TypeA && rr.A != nil && r.allowsUpstream(rr.A):
			addrs = append(addrs, rr.A)
		case rr.Type == dnsmsg.TypeAAAA && rr.AAAA != nil && r.allowsUpstream(rr.AAAA):
			addrs = append(addrs, rr.AAAA)
		}
	}
	// A response with fewer addresses than the hints we already have is not
	// an improvement, and is what a stripped-down answer would look like.
	if len(addrs) < len(rootHints) {
		return
	}

	r.primeMu.Lock()
	r.primed = addrs
	r.primedUntil = time.Now().Add(time.Duration(clampPrimeTTL(ttl)) * time.Second)
	r.primeMu.Unlock()
}

func clampPrimeTTL(ttl uint32) uint32 {
	return min(max(ttl, uint32(primeInterval.Seconds())), maxDelegationTTL)
}

// primedRoots returns the primed set if there is a current one.
func (r *Resolver) primedRoots() ([]net.IP, bool) {
	r.primeMu.Lock()
	defer r.primeMu.Unlock()
	if len(r.primed) == 0 || !r.primedUntil.After(time.Now()) {
		return nil, false
	}
	return r.primed, true
}

// primeState is the resolver's knowledge of the live root server set.
type primeState struct {
	primeMu     sync.Mutex
	primed      []net.IP
	primedUntil time.Time
}
