package dnssec

import (
	"errors"
	"fmt"
	"strings"

	"dns_resolver/dnsmsg"
)

// Denial of existence: proving, with signed records, that something is not
// there.
//
// Everything else in DNSSEC signs data that exists. The hard part is the
// other half - a server saying "no such name" or "no such type", or a
// parent saying "this child is not signed". None of those can be signed
// when the question is asked, because a zone that signed its answers on
// demand would have to keep its private key online.
//
// NSEC (RFC 4034 4) solves it by signing the gaps ahead of time. Every name
// in the zone gets a record naming the next one in canonical order, so the
// pair says "between these two there is nothing". A server proving a name
// does not exist hands over the record whose gap the name falls in.
//
// This matters most for the third case. Without it, a resolver that sees a
// referral with no DS record has to take the parent's word that the child
// is unsigned - and an attacker who strips the DS from a referral can turn
// any signed zone into an unsigned one, which is the whole of DNSSEC
// undone. That is what these functions close.

// ErrNoDenial means a response that owed us a proof did not carry one, or
// carried records that do not prove what they were sent to prove. Either
// way the response is not to be believed.
var ErrNoDenial = errors.New("denial of existence not proven")

// ErrUnsupportedDenial means the proof is there but in a form this package
// cannot read: an NSEC3 hash algorithm it does not implement, or an
// iteration count too high to be worth computing. Like an unsupported
// signature algorithm it is not evidence of tampering, so the caller treats
// the data as unvalidated rather than forged.
var ErrUnsupportedDenial = errors.New("denial proven in a form that cannot be checked here")

// denial is a section's denial records, sorted into the two forms. A proof
// is read entirely in one or the other: a zone signs with NSEC or with
// NSEC3, never with both.
type denial struct {
	nsec  []nsecRecord
	nsec3 []nsec3Record
	zone  string // for NSEC3, the zone the hashed owner names sit in
}

func collectDenial(records []dnsmsg.RR) (denial, error) {
	var d denial
	for _, rr := range records {
		if nsec, ok := rr.AsNSEC(); ok {
			d.nsec = append(d.nsec, nsecRecord{owner: rr.Name, rr: nsec})
		}
	}
	if len(d.nsec) > 0 {
		return d, nil
	}

	nsec3s, zone, err := nsec3Records(records)
	if err != nil {
		return denial{}, err
	}
	if len(nsec3s) == 0 {
		return denial{}, fmt.Errorf("%w: the response carried no NSEC or NSEC3 records", ErrNoDenial)
	}
	d.nsec3, d.zone = nsec3s, zone
	return d, nil
}

// ProveNoDS reports whether the records prove that zone has no DS record,
// which is what makes a delegation an unsigned one.
//
// Two shapes count. Usually the delegated name exists and has an NSEC of
// its own, listing the types it has: NS but not DS. The record has to come
// from the parent's side of the cut - an NSEC listing SOA is the child's
// own, and the child has no say in whether it is signed. Failing that, the
// name may not exist as an NSEC owner at all, in which case a record whose
// gap covers it says the same thing more strongly.
func ProveNoDS(records []dnsmsg.RR, zone string) error {
	d, err := collectDenial(records)
	if err != nil {
		return err
	}
	if len(d.nsec3) > 0 {
		return proveNoDSNSEC3(d.nsec3, zone)
	}
	nsecs := d.nsec

	for _, n := range nsecs {
		if !equalName(n.owner, zone) {
			continue
		}
		if n.rr.TypeInBitmap(dnsmsg.TypeSOA) {
			return fmt.Errorf("%w: NSEC for %s came from the child side of the cut", ErrNoDenial, zone)
		}
		if n.rr.TypeInBitmap(dnsmsg.TypeDS) {
			return fmt.Errorf("%w: NSEC for %s lists a DS after all", ErrNoDenial, zone)
		}
		return nil
	}
	for _, n := range nsecs {
		if n.covers(zone) {
			return nil
		}
	}
	return fmt.Errorf("%w: nothing denies a DS for %s", ErrNoDenial, zone)
}

// ProveNameError reports whether the records prove that qname does not
// exist, which is what an NXDOMAIN response claims.
//
// One gap is not enough. A zone with a wildcard answers for names that have
// no records of their own, so proving the name itself is missing leaves
// open that a wildcard should have matched it and the answer was withheld.
// The second proof closes that: the wildcard at the closest existing
// ancestor is missing too (RFC 4035 5.4).
func ProveNameError(records []dnsmsg.RR, qname string) error {
	d, err := collectDenial(records)
	if err != nil {
		return err
	}
	if len(d.nsec3) > 0 {
		return proveNameErrorNSEC3(d.nsec3, qname, d.zone)
	}
	nsecs := d.nsec

	covering := findCovering(nsecs, qname)
	if covering == nil {
		return fmt.Errorf("%w: nothing denies the name %s", ErrNoDenial, qname)
	}
	wildcard := "*." + covering.closestEncloser(qname)
	if findCovering(nsecs, wildcard) == nil {
		return fmt.Errorf("%w: %s is denied but %s is not, so a wildcard may have been withheld", ErrNoDenial, qname, wildcard)
	}
	return nil
}

// ProveNoData reports whether the records prove that qname exists but has
// no record of qtype - the NODATA answer of RFC 2308.
func ProveNoData(records []dnsmsg.RR, qname string, qtype dnsmsg.RRType) error {
	d, err := collectDenial(records)
	if err != nil {
		return err
	}
	if len(d.nsec3) > 0 {
		return proveNoDataNSEC3(d.nsec3, qname, qtype, d.zone)
	}
	nsecs := d.nsec

	for _, n := range nsecs {
		if !equalName(n.owner, qname) {
			continue
		}
		if n.rr.TypeInBitmap(qtype) {
			return fmt.Errorf("%w: NSEC for %s lists %s after all", ErrNoDenial, qname, qtype)
		}
		// A name with a CNAME has no other types, so the answer should have
		// been the CNAME rather than an empty one.
		if n.rr.TypeInBitmap(dnsmsg.TypeCNAME) {
			return fmt.Errorf("%w: %s has a CNAME that was not followed", ErrNoDenial, qname)
		}
		// An NS without an SOA is the parent's half of a delegation: the
		// answer should have been a referral, not an empty one. A DS query
		// is the exception, since a DS is answered by the parent.
		if qtype != dnsmsg.TypeDS && n.rr.TypeInBitmap(dnsmsg.TypeNS) && !n.rr.TypeInBitmap(dnsmsg.TypeSOA) {
			return fmt.Errorf("%w: %s is a delegation, so this should have been a referral", ErrNoDenial, qname)
		}
		return nil
	}

	// A name with no records of its own, but with names beneath it, has no
	// NSEC: it exists only as a branch of the tree. The gap it falls in
	// proves that, as long as the next name is one of its descendants -
	// nothing else could put it there.
	if covering := findCovering(nsecs, qname); covering != nil {
		if isProperSubdomain(covering.rr.NextDomain, qname) {
			return nil
		}
		// Otherwise the name is genuinely missing and a wildcard answered
		// for it; the wildcard is then what has to lack the type.
		wildcard := "*." + covering.closestEncloser(qname)
		for _, n := range nsecs {
			if equalName(n.owner, wildcard) && !n.rr.TypeInBitmap(qtype) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: nothing denies %s %s", ErrNoDenial, qtype, qname)
}

// ProveNoCloserMatch reports whether the records prove that qname does not
// exist in its own right, which is what a zone owes for an answer produced
// by expanding a wildcard (RFC 4035 5.3.4).
//
// Without it a wildcard record is a signature that fits every name in the
// zone: an attacker holding one signed answer for "*.example.com" could
// replay it as the answer for any name under example.com, including names
// that have real records of their own.
func ProveNoCloserMatch(records []dnsmsg.RR, qname string) error {
	d, err := collectDenial(records)
	if err != nil {
		return err
	}
	if len(d.nsec3) > 0 {
		return proveNoCloserMatchNSEC3(d.nsec3, qname, d.zone)
	}
	if findCovering(d.nsec, qname) == nil {
		return fmt.Errorf("%w: a wildcard answered for %s without proving the name itself is missing", ErrNoDenial, qname)
	}
	return nil
}

// IsWildcardExpansion reports whether a signature says its records were
// produced from a wildcard rather than stored under the name they arrived
// under. The signer writes down how many labels the name it signed had, so
// a count short of the owner's is the wildcard showing through.
func IsWildcardExpansion(owner string, sig *dnsmsg.RRSIG) bool {
	return int(sig.Labels) < len(splitName(owner))
}

// nsecRecord pairs an NSEC's parsed RDATA with its owner name, which lives
// in the record header rather than the RDATA and is half of every gap.
type nsecRecord struct {
	owner string
	rr    *dnsmsg.NSEC
}

// covers reports whether name falls strictly inside this record's gap.
//
// The last record in a zone wraps around: its next name is the apex, which
// sorts before it rather than after, and it covers everything past its
// owner.
func (n nsecRecord) covers(name string) bool {
	afterOwner := CompareNames(name, n.owner) > 0
	beforeNext := CompareNames(name, n.rr.NextDomain) < 0
	if CompareNames(n.owner, n.rr.NextDomain) >= 0 {
		return afterOwner || beforeNext
	}
	return afterOwner && beforeNext
}

// closestEncloser is the deepest existing ancestor of name, given that this
// record's gap covers it. Both ends of the gap exist, so the longest suffix
// name shares with either of them is a name that exists, and no longer one
// can - a longer one would have sorted into the gap itself.
func (n nsecRecord) closestEncloser(name string) string {
	a := commonSuffix(name, n.owner)
	b := commonSuffix(name, n.rr.NextDomain)
	if len(splitName(a)) >= len(splitName(b)) {
		return a
	}
	return b
}

func findCovering(nsecs []nsecRecord, name string) *nsecRecord {
	for i := range nsecs {
		if nsecs[i].covers(name) {
			return &nsecs[i]
		}
	}
	return nil
}

// CompareNames orders two domain names the way DNSSEC does (RFC 4034 6.1):
// by label, starting at the top of the tree, each label compared as raw
// lowercased octets. It is not the same as comparing the names as strings -
// "z.example" sorts before "a.b.example", because the rightmost labels are
// what count first.
func CompareNames(a, b string) int {
	al, bl := splitName(strings.ToLower(a)), splitName(strings.ToLower(b))
	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		if c := strings.Compare(al[i], bl[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case i < 0 && j < 0:
		return 0
	case i < 0:
		return -1 // a ran out of labels first, so it is the ancestor
	default:
		return 1
	}
}

// commonSuffix is the longest run of whole labels two names share at the
// top of the tree, which is the deepest name that is an ancestor of both.
func commonSuffix(a, b string) string {
	al, bl := splitName(strings.ToLower(a)), splitName(strings.ToLower(b))
	i, j := len(al)-1, len(bl)-1
	shared := 0
	for i >= 0 && j >= 0 && al[i] == bl[j] {
		shared++
		i--
		j--
	}
	if shared == 0 {
		return ""
	}
	return strings.Join(al[len(al)-shared:], ".")
}

func isProperSubdomain(name, zone string) bool {
	return !equalName(name, zone) && isSubdomainOrEqual(name, zone)
}
