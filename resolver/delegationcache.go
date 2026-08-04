package resolver

import (
	"container/list"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultDelegationEntries = 2000
	// Bounds on how long a delegation is reused, for the same reason the
	// message cache has them: the TTL comes from the server that sent the
	// referral. NS records for a TLD legitimately carry TTLs of a day or
	// two, so the ceiling is higher than the message cache's.
	maxDelegationTTL = 7 * 24 * 60 * 60
	minDelegationTTL = 60
)

// delegationCache remembers which servers are authoritative for a zone. A
// nil *delegationCache is a working cache that remembers nothing, so a
// Resolver built without one still resolves.
//
// It is a separate layer from the message cache, and the difference is the
// point of it: the message cache is keyed by the client's question, so it
// does nothing for the walk that answers a question it has never seen.
// Without this, every cache miss starts at a root server and asks the whole
// chain again, so looking up example.com and then example.org queries the
// root twice - wasteful for us and impolite to the root servers.
type delegationCache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[string]*delegationEntry
	order      *list.List // front = most recently used
	now        func() time.Time
}

type delegationEntry struct {
	servers []net.IP
	// secure records that this delegation was reached through a validated
	// chain. Resuming a resolution here is only sound if the keys for the
	// zone are still known; without that it has to be reached again from
	// the root, or everything under it is answered unchecked.
	secure bool
	expiry time.Time
	elem   *list.Element
}

func newDelegationCache(maxEntries int) *delegationCache {
	if maxEntries <= 0 {
		maxEntries = defaultDelegationEntries
	}
	return &delegationCache{
		maxEntries: maxEntries,
		entries:    make(map[string]*delegationEntry),
		order:      list.New(),
		now:        time.Now,
	}
}

// closestEnclosing returns the deepest cached zone that qname sits under,
// with the servers for it, so a resolution can start partway down the tree
// instead of at the root.
func (c *delegationCache) closestEnclosing(qname string) (zone string, servers []net.IP, secure, ok bool) {
	if c == nil {
		return ".", nil, false, false
	}
	name := normalizeZone(qname)

	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		if e, found := c.entries[name]; found {
			if e.expiry.After(c.now()) {
				c.order.MoveToFront(e.elem)
				return zoneName(name), append([]net.IP(nil), e.servers...), e.secure, true
			}
			c.remove(name, e)
		}
		if name == "" {
			return ".", nil, false, false
		}
		if i := strings.Index(name, "."); i >= 0 {
			name = name[i+1:]
		} else {
			name = "" // the root, which is checked on the next turn
		}
	}
}

// put records the servers for zone. ttl is the TTL of the NS records the
// delegation came in, clamped to a sane range, and secure says whether the
// walk that found it was still inside the chain of trust.
func (c *delegationCache) put(zone string, servers []net.IP, ttl uint32, secure bool) {
	if c == nil || len(servers) == 0 {
		return
	}
	ttl = min(max(ttl, minDelegationTTL), maxDelegationTTL)
	key := normalizeZone(zone)

	c.mu.Lock()
	defer c.mu.Unlock()

	if old, found := c.entries[key]; found {
		c.remove(key, old)
	}
	e := &delegationEntry{
		servers: append([]net.IP(nil), servers...),
		secure:  secure,
		expiry:  c.now().Add(time.Duration(ttl) * time.Second),
	}
	e.elem = c.order.PushFront(key)
	c.entries[key] = e

	for len(c.entries) > c.maxEntries {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		key := oldest.Value.(string)
		c.remove(key, c.entries[key])
	}
}

// forget drops a zone, for when the servers it names stop answering: a
// cached delegation that has gone stale would otherwise keep every name
// under that zone unresolvable until it expired on its own.
func (c *delegationCache) forget(zone string) {
	if c == nil {
		return
	}
	key := normalizeZone(zone)

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, found := c.entries[key]; found {
		c.remove(key, e)
	}
}

// remove must be called with the mutex held.
func (c *delegationCache) remove(key string, e *delegationEntry) {
	if e == nil {
		return
	}
	c.order.Remove(e.elem)
	delete(c.entries, key)
}

// normalizeZone maps a zone to its cache key: lowercase, no trailing dot,
// with the root as the empty string so that walking up by cutting labels
// ends there.
func normalizeZone(zone string) string {
	return strings.ToLower(strings.TrimSuffix(zone, "."))
}

func zoneName(key string) string {
	if key == "" {
		return "."
	}
	return key
}
