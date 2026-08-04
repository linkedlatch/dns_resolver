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
		// unvalidated from here on. The parent has to prove that, though -
		// otherwise stripping the DS records out of a referral downgrades
		// any signed zone to an unsigned one, and the chain of trust can be
		// cut at every link.
		if _, err := r.checkDenial(parent, resp.Authorities, func(nsecs []dnsmsg.RR) error {
			return dnssec.ProveNoDS(nsecs, zone)
		}); err != nil {
			return insecure, fmt.Errorf("%w: unsigned delegation of %s: %v", ErrBogus, zone, err)
		}
		return insecure, nil
	}
	if _, err := r.verifyRRSet(dsSet, resp.Authorities, parent.keys); err != nil {
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
	if len(keys) == 0 {
		// The zone is signed only with algorithms this resolver cannot
		// check. Carrying on as "secure with no keys" would make every
		// answer below it fail for want of a signature we could never
		// verify; unsigned is the honest description of what we know.
		return insecure, nil
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
				if _, err := r.verifyRRSetWithKeys(keySet, resp.Answers, []*dnsmsg.DNSKEY{key}); err == nil {
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
// keys, with sigs being the section the RRSIGs arrived in. It returns the
// signature that checked out, which says more than "valid": how many labels
// the signer wrote down is what reveals a wildcard.
func (r *Resolver) verifyRRSet(rrset []dnsmsg.RR, sigs []dnsmsg.RR, keys []*dnsmsg.DNSKEY) (*dnsmsg.RRSIG, error) {
	return r.verifyRRSetWithKeys(rrset, sigs, keys)
}

func (r *Resolver) verifyRRSetWithKeys(rrset []dnsmsg.RR, section []dnsmsg.RR, keys []*dnsmsg.DNSKEY) (*dnsmsg.RRSIG, error) {
	if len(rrset) == 0 {
		return nil, errors.New("nothing to verify")
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys to verify with")
	}
	covering := rrsigsFor(section, rrset[0].Name, rrset[0].Type)
	if len(covering) == 0 {
		return nil, fmt.Errorf("no RRSIG covers %s %s", rrset[0].Name, rrset[0].Type)
	}

	var lastErr error
	unsupported := false
	for _, sig := range covering {
		for _, key := range keys {
			err := dnssec.VerifyRRSet(rrset, sig, key, r.now())
			if err == nil {
				return sig, nil
			}
			if errors.Is(err, dnssec.ErrUnsupportedAlgorithm) {
				unsupported = true
			}
			lastErr = err
		}
	}
	if unsupported {
		return nil, dnssec.ErrUnsupportedAlgorithm
	}
	return nil, lastErr
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
		sig, err := r.verifyRRSet(rrset, resp.Answers, sec.keys)
		switch {
		case err == nil:
		case errors.Is(err, dnssec.ErrUnsupportedAlgorithm):
			// Signed with something we cannot check: no evidence either
			// way, so the answer stands but is not called secure.
			return false, nil
		default:
			return false, fmt.Errorf("%w: %s %s: %v", ErrBogus, rr.Name, rr.Type, err)
		}

		// A signature made for a wildcard fits every name in the zone, so a
		// valid one is not by itself evidence that this name was the one
		// answered for. The zone owes a proof that the name has nothing of
		// its own (RFC 4035 5.3.4); without it, one signed wildcard answer
		// could be replayed as the answer for any name under it.
		if dnssec.IsWildcardExpansion(rr.Name, sig) {
			proven, err := r.checkDenial(sec, resp.Authorities, func(nsecs []dnsmsg.RR) error {
				return dnssec.ProveNoCloserMatch(nsecs, rr.Name)
			})
			if err != nil {
				return false, fmt.Errorf("%w: %s %s: %v", ErrBogus, rr.Name, rr.Type, err)
			}
			if !proven {
				return false, nil
			}
		}
	}
	return true, nil
}

// checkDenial runs one of the proofs in the dnssec package over the NSEC
// records of a response, having first checked that those records are
// themselves signed by the zone.
//
// It separates three outcomes that a plain error cannot. A proof that holds
// returns true. A proof in a form not checked here - NSEC3 - returns false
// without an error, because a resolver that cannot read the evidence has
// learned nothing either way and should treat the data as unvalidated
// rather than as an attack. Anything else is an error: the response owed a
// proof and did not produce one.
func (r *Resolver) checkDenial(sec secState, section []dnsmsg.RR, prove func([]dnsmsg.RR) error) (bool, error) {
	if !r.validate || !sec.secure {
		return false, nil
	}
	switch err := prove(r.verifiedNSECs(section, sec.keys)); {
	case err == nil:
		return true, nil
	case errors.Is(err, dnssec.ErrUnsupportedDenial), errors.Is(err, dnssec.ErrUnsupportedAlgorithm):
		return false, nil
	default:
		return false, err
	}
}

// verifiedNSECs returns the denial records of a section that carry a valid
// signature, dropping the rest.
//
// Unsigned NSEC records are worth nothing: the point of a gap is that the
// zone committed to it in advance, and anyone can write one down. NSEC3
// records are passed through unverified because nothing here reads them
// either way - their presence only tells the proof which form it is looking
// at, and the caller treats that as "not checked".
func (r *Resolver) verifiedNSECs(section []dnsmsg.RR, keys []*dnsmsg.DNSKEY) []dnsmsg.RR {
	var out []dnsmsg.RR
	checked := make(map[string]bool)
	for _, rr := range section {
		switch rr.Type {
		case dnsmsg.TypeNSEC3:
			out = append(out, rr)
		case dnsmsg.TypeNSEC:
			owner := normalizeName(rr.Name)
			if checked[owner] {
				continue
			}
			checked[owner] = true
			rrset := recordsOfType(section, dnsmsg.TypeNSEC, rr.Name)
			if _, err := r.verifyRRSet(rrset, section, keys); err == nil {
				out = append(out, rrset...)
			}
		}
	}
	return out
}
