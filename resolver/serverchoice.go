package resolver

import (
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"
)

const (
	// unknownRTT is what a server that has never answered is assumed to
	// cost. Optimistic on purpose: a server nobody has tried should get
	// tried, not left behind whichever one happened to answer first.
	unknownRTT = 50 * time.Millisecond
	// timeoutPenalty is charged to a server that did not answer, so it
	// falls behind the working ones without being struck off - it may be
	// the only one that has the data.
	timeoutPenalty = 2 * time.Second
	// rttSmoothing weights a new measurement against the running average,
	// so one slow answer does not condemn a server.
	rttSmoothing = 0.25
	// maxRTTEntries bounds the table; the entries are small, and a resolver
	// only ever talks to so many name servers.
	maxRTTEntries = 8192
)

// rttTracker remembers how quickly each name server has answered.
//
// Without it every resolution tries the same server first, which loads one
// machine, wastes time whenever it is the slow one, and tells an off-path
// attacker exactly which server to race. With it, the ones that answer
// quickly are preferred and the rest are still tried.
type rttTracker struct {
	mu      sync.Mutex
	entries map[string]time.Duration
}

func newRTTTracker() *rttTracker {
	return &rttTracker{entries: make(map[string]time.Duration)}
}

func (t *rttTracker) get(ip net.IP) time.Duration {
	if t == nil {
		return unknownRTT
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if d, ok := t.entries[ip.String()]; ok {
		return d
	}
	return unknownRTT
}

// observe folds a new measurement into the running average.
func (t *rttTracker) observe(ip net.IP, took time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	key := ip.String()
	if current, ok := t.entries[key]; ok {
		t.entries[key] = time.Duration(float64(current)*(1-rttSmoothing) + float64(took)*rttSmoothing)
		return
	}
	if len(t.entries) >= maxRTTEntries {
		// Drop an arbitrary entry rather than grow without bound. Which one
		// hardly matters: losing a measurement costs one slow query.
		for k := range t.entries {
			delete(t.entries, k)
			break
		}
	}
	t.entries[key] = took
}

// order returns the servers to try, fastest first, with ties broken at
// random so that equally good servers share the load and an attacker cannot
// predict which one a query will go to.
func (t *rttTracker) order(servers []net.IP) []net.IP {
	out := slices.Clone(servers)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	if t == nil {
		return out
	}
	slices.SortStableFunc(out, func(a, b net.IP) int {
		return int(t.get(a) - t.get(b))
	})
	return out
}
