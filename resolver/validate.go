package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnssec"
)

// ErrBogus means a response carried signatures that did not check out, or
// was missing signatures a signed zone owes us. It is deliberately not the
// same as "no answer": data that fails validation is data someone tampered
// with, and passing it on with a note would defeat the point.
var ErrBogus = errors.New("DNSSEC validation failed")

// secState is what the walk knows about the zone it is currently in.
//
// A resolution starts secure at the root, whose key is vouched for by a
// trust anchor compiled in here, and each delegation either carries that
// security down to the child (a DS record proving which key the child
// signs with) or ends it (no DS: the child is simply unsigned).
type secState struct {
	secure bool
	keys   []*dnsmsg.DNSKEY
}

// insecure is the state below an unsigned delegation: nothing further down
// can be validated, and nothing further down claims to be.
var insecure = secState{}

// keyCache holds DNSKEY sets that have already been validated, so a
// resolution does not re-fetch and re-verify the root and TLD keys every
// time. Entries are dropped by TTL like any other DNS data.
type keyCache struct {
	mu      sync.Mutex
	entries map[string]keyEntry
	now     func() time.Time
}

type keyEntry struct {
	keys   []*dnsmsg.DNSKEY
	expiry time.Time
}

func newKeyCache() *keyCache {
	return &keyCache{entries: make(map[string]keyEntry), now: time.Now}
}

func (c *keyCache) get(zone string) ([]*dnsmsg.DNSKEY, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.entries[normalizeZone(zone)]
	if !found || !e.expiry.After(c.now()) {
		return nil, false
	}
	return e.keys, true
}

func (c *keyCache) put(zone string, keys []*dnsmsg.DNSKEY, ttl uint32) {
	if c == nil || len(keys) == 0 {
		return
	}
	ttl = min(max(ttl, minDelegationTTL), maxDelegationTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[normalizeZone(zone)] = keyEntry{
		keys:   keys,
		expiry: c.now().Add(time.Duration(ttl) * time.Second),
	}
}

// rootState establishes the starting point of every validated resolution:
// the root's own keys, checked against the trust anchor.
func (r *Resolver) rootState(ctx context.Context, servers []net.IP) (secState, error) {
	keys, err := r.zoneKeys(ctx, ".", servers, r.trustAnchors())
	if err != nil {
		return insecure, err
	}
	return secState{secure: true, keys: keys}, nil
}

// crossDelegation carries validation across a zone boundary. The DS records
// live in the parent's referral, signed by the parent, which is what makes
// this possible without a separate query: the parent tells us, in a way we
// can check, which key the child signs with.
func (r *Resolver) crossDelegation(ctx context.Context, parent secState, resp *dnsmsg.Message, zone string, servers []net.IP) (secState, error) {
	if !parent.secure {
		return insecure, nil // already below an unsigned delegation
	}

	dsSet := recordsOfType(resp.Authorities, dnsmsg.TypeDS, zone)
	if len(dsSet) == 0 {
		// No DS: the child is unsigned, and everything under it is
		// unvalidated from here on.
		//
		// This is the one step taken on trust. Proving the absence of a DS
		// needs the NSEC or NSEC3 records that would deny it, which this
		// resolver does not yet check, so an attacker able to strip the DS
		// records from a referral can downgrade a signed zone to unsigned.
		return insecure, nil
	}
	if err := r.verifyRRSet(dsSet, resp.Authorities, parent.keys); err != nil {
		return insecure, fmt.Errorf("%w: DS for %s: %v", ErrBogus, zone, err)
	}

	var anchors []dnsmsg.DS
	for _, rr := range dsSet {
		if ds, ok := rr.AsDS(); ok {
			anchors = append(anchors, *ds)
		}
	}
	keys, err := r.zoneKeys(ctx, zone, servers, anchors)
	if err != nil {
		return insecure, err
	}
	return secState{secure: true, keys: keys}, nil
}

// zoneKeys fetches the DNSKEY set for zone from its own servers and accepts
// it only if one of the keys matches a DS (or trust anchor) and that key
// signed the set. The self-signature is what ties the whole set to the one
// key the parent vouched for.
func (r *Resolver) zoneKeys(ctx context.Context, zone string, servers []net.IP, anchors []dnsmsg.DS) ([]*dnsmsg.DNSKEY, error) {
	if keys, ok := r.keys.get(zone); ok {
		return keys, nil
	}

	resp, _, err := r.queryServers(ctx, servers, zone, dnsmsg.TypeDNSKEY)
	if err != nil {
		return nil, fmt.Errorf("fetch DNSKEY for %s: %w", zone, err)
	}
	keySet := recordsOfType(resp.Answers, dnsmsg.TypeDNSKEY, zone)
	if len(keySet) == 0 {
		return nil, fmt.Errorf("%w: %s has a DS but published no DNSKEY", ErrBogus, zone)
	}

	keys := make([]*dnsmsg.DNSKEY, 0, len(keySet))
	for _, rr := range keySet {
		if key, ok := rr.AsDNSKEY(); ok {
			keys = append(keys, key)
		}
	}

	// Find a key the parent vouched for, and check it signed this set.
	var unsupported bool
	verified := false
	for _, key := range keys {
		for i := range anchors {
			switch err := dnssec.VerifyDS(zone, key, &anchors[i]); {
			case err == nil:
				if err := r.verifyRRSetWithKeys(keySet, resp.Answers, []*dnsmsg.DNSKEY{key}); err == nil {
					verified = true
				} else if errors.Is(err, dnssec.ErrUnsupportedAlgorithm) {
					unsupported = true
				}
			case errors.Is(err, dnssec.ErrUnsupportedAlgorithm):
				unsupported = true
			}
			if verified {
				break
			}
		}
		if verified {
			break
		}
	}
	if !verified {
		if unsupported {
			// The zone is signed only with algorithms we cannot check. RFC
			// 4035 treats that as unsigned rather than forged: we have no
			// evidence either way.
			return nil, nil
		}
		return nil, fmt.Errorf("%w: no DNSKEY of %s matches its DS", ErrBogus, zone)
	}

	r.keys.put(zone, keys, minTTLOf(keySet))
	return keys, nil
}

// verifyRRSet checks that rrset is covered by a valid signature from one of
// keys, with sigs being the section the RRSIGs arrived in.
func (r *Resolver) verifyRRSet(rrset []dnsmsg.RR, sigs []dnsmsg.RR, keys []*dnsmsg.DNSKEY) error {
	return r.verifyRRSetWithKeys(rrset, sigs, keys)
}

func (r *Resolver) verifyRRSetWithKeys(rrset []dnsmsg.RR, section []dnsmsg.RR, keys []*dnsmsg.DNSKEY) error {
	if len(rrset) == 0 {
		return errors.New("nothing to verify")
	}
	if len(keys) == 0 {
		return errors.New("no keys to verify with")
	}
	covering := rrsigsFor(section, rrset[0].Name, rrset[0].Type)
	if len(covering) == 0 {
		return fmt.Errorf("no RRSIG covers %s %s", rrset[0].Name, rrset[0].Type)
	}

	var lastErr error
	unsupported := false
	for _, sig := range covering {
		for _, key := range keys {
			err := dnssec.VerifyRRSet(rrset, sig, key, r.now())
			if err == nil {
				return nil
			}
			if errors.Is(err, dnssec.ErrUnsupportedAlgorithm) {
				unsupported = true
			}
			lastErr = err
		}
	}
	if unsupported {
		return dnssec.ErrUnsupportedAlgorithm
	}
	return lastErr
}

// rrsigsFor picks the signatures in a section that claim to cover a
// particular name and type.
func rrsigsFor(section []dnsmsg.RR, name string, qtype dnsmsg.RRType) []*dnsmsg.RRSIG {
	var out []*dnsmsg.RRSIG
	for _, rr := range section {
		if rr.Type != dnsmsg.TypeRRSIG || !equalName(rr.Name, name) {
			continue
		}
		if sig, ok := rr.AsRRSIG(); ok && sig.TypeCovered == qtype {
			out = append(out, sig)
		}
	}
	return out
}

func recordsOfType(section []dnsmsg.RR, qtype dnsmsg.RRType, name string) []dnsmsg.RR {
	var out []dnsmsg.RR
	for _, rr := range section {
		if rr.Type == qtype && rr.Class == dnsmsg.ClassIN && equalName(rr.Name, name) {
			out = append(out, rr)
		}
	}
	return out
}

func minTTLOf(rrs []dnsmsg.RR) uint32 {
	if len(rrs) == 0 {
		return 0
	}
	m := rrs[0].TTL
	for _, rr := range rrs[1:] {
		if rr.TTL < m {
			m = rr.TTL
		}
	}
	return m
}

func (r *Resolver) now() time.Time {
	if r.clock != nil {
		return r.clock()
	}
	return time.Now()
}

// trustAnchors returns the keys the whole system is bootstrapped from.
func (r *Resolver) trustAnchors() []dnsmsg.DS {
	if r.anchors != nil {
		return r.anchors
	}
	return RootAnchors()
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// startingSecurity is the security state a resolution begins in: validated
// root keys, or the keys of the cached zone it is starting from if those
// have already been checked. When validation is off, or nothing is known
// about the starting zone, the walk proceeds unvalidated.
func (r *Resolver) startingSecurity(ctx context.Context, zone string, servers []net.IP) (secState, error) {
	if !r.validate {
		return insecure, nil
	}
	if normalizeName(zone) == "" {
		return r.rootState(ctx, servers)
	}
	if keys, ok := r.keys.get(zone); ok {
		return secState{secure: true, keys: keys}, nil
	}
	// Starting mid-tree without the keys for that zone would mean trusting
	// it on nothing; the caller falls back to walking from the root.
	return insecure, nil
}

// validateAnswer checks the records a response is answering with. Each set
// of one name and type has to carry a signature from the zone's keys: a
// signed zone that answers without one has had the signature stripped, and
// there is no way to tell that apart from an answer that was never signed.
func (r *Resolver) validateAnswer(sec secState, resp *dnsmsg.Message, records []dnsmsg.RR) (bool, error) {
	if !r.validate || !sec.secure || len(records) == 0 {
		return false, nil
	}

	type nameType struct {
		name  string
		qtype dnsmsg.RRType
	}
	seen := make(map[nameType]bool)
	for _, rr := range records {
		k := nameType{name: normalizeName(rr.Name), qtype: rr.Type}
		if seen[k] {
			continue
		}
		seen[k] = true

		rrset := recordsOfType(records, rr.Type, rr.Name)
		err := r.verifyRRSet(rrset, resp.Answers, sec.keys)
		switch {
		case err == nil:
		case errors.Is(err, dnssec.ErrUnsupportedAlgorithm):
			// Signed with something we cannot check: no evidence either
			// way, so the answer stands but is not called secure.
			return false, nil
		default:
			return false, fmt.Errorf("%w: %s %s: %v", ErrBogus, rr.Name, rr.Type, err)
		}
	}
	return true, nil
}
