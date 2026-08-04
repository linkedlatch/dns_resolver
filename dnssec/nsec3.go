package dnssec

import (
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"

	"dns_resolver/dnsmsg"
)

// NSEC3 is NSEC over hashes.
//
// An NSEC chain can be walked: ask for a name that does not exist, get back
// the record naming the next one that does, ask for the name after that,
// and the whole zone comes out one record at a time. NSEC3 (RFC 5155)
// closes that by ordering hashes of the names instead of the names, so a
// gap tells the asker that nothing hashes into it and nothing more.
//
// The cost is that a verifier can no longer read the gaps directly. It has
// to hash the name it is asking about, find which gap that hash falls in,
// and - because a hash says nothing about the tree structure the way a name
// does - work out separately which part of the name actually exists. That
// last step is the "closest encloser proof" below, and it is most of what
// makes NSEC3 harder than NSEC.

// nsec3HashSHA1 is the only hash algorithm NSEC3 defines (RFC 5155 5). A
// zone using anything else is one we cannot check.
const nsec3HashSHA1 = 1

// maxNSEC3Iterations bounds the extra hashing a zone can make us do. Each
// iteration is work the zone chooses and we perform, once per name, which
// makes a large count a way to spend our CPU rather than a way to hide
// anything: the protection iterations were meant to add against dictionary
// attacks was always slight, and RFC 9276 now says to use none at all.
// Above the limit the zone is treated as unvalidatable rather than as an
// attack, which is what a resolver that cannot afford the work can honestly
// say.
const maxNSEC3Iterations = 100

// base32Hex is the encoding NSEC3 owner names use: base32 with the
// "extended hex" alphabet, unpadded, so that the encoded hashes sort in the
// same order as the raw ones.
var base32Hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// nsec3Record pairs an NSEC3's parsed RDATA with the hash in its owner
// name, which is the near end of the gap.
type nsec3Record struct {
	owner string // the first label of the owner name, the encoded hash
	zone  string // the rest of it, which is the zone the record belongs to
	rr    *dnsmsg.NSEC3
}

// covers reports whether a hash falls strictly inside this record's gap,
// with the same wrap-around at the end of the zone as NSEC.
func (n nsec3Record) covers(hash string) bool {
	next := strings.ToUpper(base32Hex.EncodeToString(n.rr.NextHashed))
	afterOwner := hash > n.owner
	beforeNext := hash < next
	if n.owner >= next {
		return afterOwner || beforeNext
	}
	return afterOwner && beforeNext
}

func (n nsec3Record) matches(hash string) bool { return hash == n.owner }

// hashName is the hashed owner name of a name, in the form NSEC3 owner
// names use. The hash is iterated with the salt appended each round (RFC
// 5155 5), and the name is hashed in the same canonical wire form
// signatures are made over.
func (n nsec3Record) hashName(name string) (string, error) {
	if n.rr.Algorithm != nsec3HashSHA1 {
		return "", fmt.Errorf("%w: NSEC3 hash algorithm %d", ErrUnsupportedDenial, n.rr.Algorithm)
	}
	if n.rr.Iterations > maxNSEC3Iterations {
		return "", fmt.Errorf("%w: NSEC3 asks for %d iterations", ErrUnsupportedDenial, n.rr.Iterations)
	}
	wire, err := canonicalName(name)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(append(wire, n.rr.Salt...))
	for i := 0; i < int(n.rr.Iterations); i++ {
		sum = sha1.Sum(append(sum[:], n.rr.Salt...))
	}
	return strings.ToUpper(base32Hex.EncodeToString(sum[:])), nil
}

// findMatch returns the record whose owner is the hash of name.
func findMatch(nsec3s []nsec3Record, name string) (*nsec3Record, error) {
	for i := range nsec3s {
		hash, err := nsec3s[i].hashName(name)
		if err != nil {
			return nil, err
		}
		if nsec3s[i].matches(hash) {
			return &nsec3s[i], nil
		}
	}
	return nil, nil
}

// findCover returns the record whose gap contains the hash of name.
func findCover(nsec3s []nsec3Record, name string) (*nsec3Record, error) {
	for i := range nsec3s {
		hash, err := nsec3s[i].hashName(name)
		if err != nil {
			return nil, err
		}
		if nsec3s[i].covers(hash) {
			return &nsec3s[i], nil
		}
	}
	return nil, nil
}

// closestEncloser finds the deepest ancestor of name that the records show
// exists, along with the "next closer" name: the one label more of name
// below it, which is where the tree stops.
//
// This is the step NSEC has for free. A gap between two names shows what
// lies between them in a tree everyone can read; a gap between two hashes
// shows nothing about structure, so the verifier has to hash each ancestor
// in turn until one of them is found in the zone.
func closestEncloser(nsec3s []nsec3Record, name, zone string) (encloser, nextCloser string, err error) {
	labels := splitName(name)
	zoneLabels := len(splitName(zone))
	if len(labels) < zoneLabels {
		return "", "", fmt.Errorf("%w: %s is not inside %s", ErrNoDenial, name, zone)
	}

	// Start one label below the name itself: for a name error the name does
	// not exist, and for a wildcard the record was expanded rather than
	// stored, so neither is its own closest encloser.
	for i := 1; len(labels)-i >= zoneLabels; i++ {
		candidate := strings.Join(labels[i:], ".")
		match, err := findMatch(nsec3s, candidate)
		if err != nil {
			return "", "", err
		}
		if match != nil {
			return candidate, strings.Join(labels[i-1:], "."), nil
		}
	}
	return "", "", fmt.Errorf("%w: no NSEC3 shows which part of %s exists", ErrNoDenial, name)
}

// proveNoDSNSEC3 shows that zone has no DS record.
//
// Opt-out is the second way, and the reason com can be signed at all: a
// record with the flag set says only that the names hashing into its gap
// have no signed delegation, which is exactly the claim being made here.
func proveNoDSNSEC3(nsec3s []nsec3Record, zone string) error {
	match, err := findMatch(nsec3s, zone)
	if err != nil {
		return err
	}
	if match != nil {
		if match.rr.TypeInBitmap(dnsmsg.TypeSOA) {
			return fmt.Errorf("%w: NSEC3 for %s came from the child side of the cut", ErrNoDenial, zone)
		}
		if match.rr.TypeInBitmap(dnsmsg.TypeDS) {
			return fmt.Errorf("%w: NSEC3 for %s lists a DS after all", ErrNoDenial, zone)
		}
		return nil
	}

	cover, err := findCover(nsec3s, zone)
	if err != nil {
		return err
	}
	if cover != nil && cover.rr.OptOut() {
		return nil
	}
	if cover != nil {
		return fmt.Errorf("%w: %s falls in a gap that does not opt out, so it should have its own NSEC3", ErrNoDenial, zone)
	}
	return fmt.Errorf("%w: nothing denies a DS for %s", ErrNoDenial, zone)
}

// proveNameErrorNSEC3 shows that qname does not exist: the deepest part of
// it that does exist, that the next label down is in a gap, and that the
// wildcard which could have answered for it is in a gap too.
func proveNameErrorNSEC3(nsec3s []nsec3Record, qname, zone string) error {
	encloser, nextCloser, err := closestEncloser(nsec3s, qname, zone)
	if err != nil {
		return err
	}
	cover, err := findCover(nsec3s, nextCloser)
	if err != nil {
		return err
	}
	if cover == nil {
		return fmt.Errorf("%w: nothing denies %s, the next name below %s", ErrNoDenial, nextCloser, encloser)
	}
	wildcard, err := findCover(nsec3s, "*."+encloser)
	if err != nil {
		return err
	}
	if wildcard == nil {
		return fmt.Errorf("%w: %s is denied but *.%s is not, so a wildcard may have been withheld", ErrNoDenial, qname, encloser)
	}
	return nil
}

// proveNoDataNSEC3 shows that qname exists but holds no record of qtype.
func proveNoDataNSEC3(nsec3s []nsec3Record, qname string, qtype dnsmsg.RRType, zone string) error {
	match, err := findMatch(nsec3s, qname)
	if err != nil {
		return err
	}
	if match != nil {
		if match.rr.TypeInBitmap(qtype) {
			return fmt.Errorf("%w: NSEC3 for %s lists %s after all", ErrNoDenial, qname, qtype)
		}
		if match.rr.TypeInBitmap(dnsmsg.TypeCNAME) {
			return fmt.Errorf("%w: %s has a CNAME that was not followed", ErrNoDenial, qname)
		}
		if qtype != dnsmsg.TypeDS && match.rr.TypeInBitmap(dnsmsg.TypeNS) && !match.rr.TypeInBitmap(dnsmsg.TypeSOA) {
			return fmt.Errorf("%w: %s is a delegation, so this should have been a referral", ErrNoDenial, qname)
		}
		return nil
	}

	// No record for the name itself. A DS query may still be answered by an
	// opt-out gap (RFC 5155 8.6), and any other type only by a wildcard that
	// exists but lacks it.
	encloser, nextCloser, err := closestEncloser(nsec3s, qname, zone)
	if err != nil {
		return err
	}
	cover, err := findCover(nsec3s, nextCloser)
	if err != nil {
		return err
	}
	if cover == nil {
		return fmt.Errorf("%w: nothing denies %s %s", ErrNoDenial, qtype, qname)
	}
	if qtype == dnsmsg.TypeDS && cover.rr.OptOut() {
		return nil
	}
	wildcard, err := findMatch(nsec3s, "*."+encloser)
	if err != nil {
		return err
	}
	if wildcard != nil && !wildcard.rr.TypeInBitmap(qtype) {
		return nil
	}
	return fmt.Errorf("%w: nothing denies %s %s", ErrNoDenial, qtype, qname)
}

// proveNoCloserMatchNSEC3 shows that a wildcard was entitled to answer for
// qname, by showing that the name one label below the wildcard's own parent
// does not exist.
func proveNoCloserMatchNSEC3(nsec3s []nsec3Record, qname, zone string) error {
	_, nextCloser, err := closestEncloser(nsec3s, qname, zone)
	if err != nil {
		return err
	}
	cover, err := findCover(nsec3s, nextCloser)
	if err != nil {
		return err
	}
	if cover == nil {
		return fmt.Errorf("%w: a wildcard answered for %s without proving %s is missing", ErrNoDenial, qname, nextCloser)
	}
	return nil
}

// nsec3Records collects the NSEC3 records of a section. They all have to
// belong to one zone and share one set of hash parameters: a mixture is
// either a zone mid-rollover, which cannot be reasoned about safely, or an
// attempt to assemble a proof out of records from two places.
func nsec3Records(records []dnsmsg.RR) ([]nsec3Record, string, error) {
	var out []nsec3Record
	zone := ""
	for _, rr := range records {
		n, ok := rr.AsNSEC3()
		if !ok {
			continue
		}
		label, rest, found := strings.Cut(strings.TrimSuffix(rr.Name, "."), ".")
		if label == "" {
			return nil, "", fmt.Errorf("%w: NSEC3 owner %q carries no hash", ErrNoDenial, rr.Name)
		}
		if !found {
			rest = "." // an NSEC3 belonging to the root zone itself
		}
		if zone == "" {
			zone = rest
		} else if !equalName(rest, zone) {
			return nil, "", fmt.Errorf("%w: NSEC3 records from both %s and %s", ErrNoDenial, zone, rest)
		}
		if len(out) > 0 && !sameParameters(out[0].rr, n) {
			return nil, "", fmt.Errorf("%w: NSEC3 records with different hash parameters", ErrNoDenial)
		}
		out = append(out, nsec3Record{owner: strings.ToUpper(label), zone: rest, rr: n})
	}
	return out, zone, nil
}

func sameParameters(a, b *dnsmsg.NSEC3) bool {
	return a.Algorithm == b.Algorithm && a.Iterations == b.Iterations &&
		string(a.Salt) == string(b.Salt)
}
