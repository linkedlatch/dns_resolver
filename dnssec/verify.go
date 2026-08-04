// Package dnssec verifies DNSSEC signatures: that an RRset was signed by a
// key of the zone it claims to come from, and that the key itself is
// vouched for by the zone's parent, up to a trust anchor.
//
// The point is that a resolver otherwise believes whatever the server it is
// talking to says. Everything before this package - matching query IDs,
// bailiwick rules, refusing odd addresses - narrows who can lie; this is
// the first thing that can tell whether the data itself is authentic.
package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"dns_resolver/dnsmsg"
)

// ErrUnsupportedAlgorithm means the signature or digest uses an algorithm
// this resolver does not implement. It is deliberately distinct from a
// failed check: an unsupported algorithm says nothing about authenticity,
// and RFC 4035 has a resolver treat such a zone as unsigned rather than
// forged.
var ErrUnsupportedAlgorithm = errors.New("unsupported DNSSEC algorithm")

// Signature algorithms (RFC 8624 gives the current recommendations).
const (
	algRSASHA256       = 8
	algRSASHA512       = 10
	algECDSAP256SHA256 = 13
	algECDSAP384SHA384 = 14
	algEd25519         = 15
)

// DS digest types.
const (
	digestSHA256 = 2
	digestSHA384 = 4
)

// VerifyRRSet reports whether sig is a valid signature by key over rrset.
//
// Every part of this is a check an attacker would otherwise get to skip:
// the signature has to be current, made by this key, over this exact set of
// records, by a zone entitled to sign for the owner name.
func VerifyRRSet(rrset []dnsmsg.RR, sig *dnsmsg.RRSIG, key *dnsmsg.DNSKEY, now time.Time) error {
	if len(rrset) == 0 {
		return errors.New("no records to verify")
	}
	owner := rrset[0].Name
	for _, rr := range rrset {
		if rr.Type != sig.TypeCovered || !equalName(rr.Name, owner) {
			return errors.New("RRset is not a single set of one name and type")
		}
	}

	if sig.Algorithm != key.Algorithm {
		return fmt.Errorf("signature algorithm %d does not match key algorithm %d", sig.Algorithm, key.Algorithm)
	}
	if sig.KeyTag != key.KeyTag() {
		return fmt.Errorf("signature names key %d, this key is %d", sig.KeyTag, key.KeyTag())
	}
	if !key.IsZoneKey() {
		return errors.New("key is not a zone key")
	}
	// The signer must be the owner's zone or an ancestor of it; otherwise
	// any zone could sign records for any name.
	if !isSubdomainOrEqual(owner, sig.SignerName) {
		return fmt.Errorf("signer %s is not authoritative for %s", sig.SignerName, owner)
	}
	if err := checkValidityPeriod(sig, now); err != nil {
		return err
	}

	signed, err := signedData(rrset, sig)
	if err != nil {
		return err
	}
	return verifySignature(sig.Algorithm, key.PublicKey, signed, sig.Signature)
}

// checkValidityPeriod enforces the signature's own lifetime. The timestamps
// are seconds since the epoch in 32 bits, which wraps in 2106, so RFC 4034
// compares them in serial-number arithmetic rather than as plain integers.
func checkValidityPeriod(sig *dnsmsg.RRSIG, now time.Time) error {
	t := uint32(now.Unix())
	if serialBefore(t, sig.Inception) {
		return fmt.Errorf("signature is not valid until %s", time.Unix(int64(sig.Inception), 0).UTC())
	}
	if serialBefore(sig.Expiration, t) {
		return fmt.Errorf("signature expired at %s", time.Unix(int64(sig.Expiration), 0).UTC())
	}
	return nil
}

// serialBefore reports whether a is before b in the circular arithmetic of
// RFC 1982.
func serialBefore(a, b uint32) bool {
	return a != b && (b-a) < 1<<31
}

// signedData rebuilds the exact bytes the signer hashed: the RRSIG's own
// fields (without the signature) followed by the RRset in canonical form
// (RFC 4034 6). Getting this byte-for-byte right is the whole difficulty of
// verification - any difference just looks like a bad signature.
func signedData(rrset []dnsmsg.RR, sig *dnsmsg.RRSIG) ([]byte, error) {
	var buf bytes.Buffer

	// The RRSIG RDATA up to but excluding the signature field.
	buf.Write(uint16be(uint16(sig.TypeCovered)))
	buf.WriteByte(sig.Algorithm)
	buf.WriteByte(sig.Labels)
	buf.Write(uint32be(sig.OriginalTTL))
	buf.Write(uint32be(sig.Expiration))
	buf.Write(uint32be(sig.Inception))
	buf.Write(uint16be(sig.KeyTag))
	signer, err := canonicalName(sig.SignerName)
	if err != nil {
		return nil, err
	}
	buf.Write(signer)

	owner, err := signedOwnerName(rrset[0].Name, sig)
	if err != nil {
		return nil, err
	}

	// Canonical ordering: by RDATA bytes, with duplicates dropped. A
	// verifier that ordered them differently would hash different bytes.
	type encoded struct {
		rdata []byte
	}
	records := make([]encoded, 0, len(rrset))
	for _, rr := range rrset {
		rdata, err := canonicalRDATA(rr)
		if err != nil {
			return nil, err
		}
		records = append(records, encoded{rdata: rdata})
	}
	slices.SortFunc(records, func(a, b encoded) int { return bytes.Compare(a.rdata, b.rdata) })

	for i, rec := range records {
		if i > 0 && bytes.Equal(rec.rdata, records[i-1].rdata) {
			continue
		}
		buf.Write(owner)
		buf.Write(uint16be(uint16(sig.TypeCovered)))
		buf.Write(uint16be(uint16(dnsmsg.ClassIN)))
		buf.Write(uint32be(sig.OriginalTTL)) // the signer's TTL, not the one we received
		buf.Write(uint16be(uint16(len(rec.rdata))))
		buf.Write(rec.rdata)
	}
	return buf.Bytes(), nil
}

// signedOwnerName is the owner name as the signer wrote it. When the RRSIG
// covers fewer labels than the name has, the records came from a wildcard
// and were signed under "*" plus the labels that were matched.
func signedOwnerName(owner string, sig *dnsmsg.RRSIG) ([]byte, error) {
	labels := splitName(owner)
	if int(sig.Labels) > len(labels) {
		return nil, fmt.Errorf("RRSIG claims %d labels, owner %s has %d", sig.Labels, owner, len(labels))
	}
	if int(sig.Labels) < len(labels) {
		owner = strings.Join(append([]string{"*"}, labels[len(labels)-int(sig.Labels):]...), ".")
	}
	return canonicalName(owner)
}

// canonicalRDATA is a record's RDATA in wire form, uncompressed and with
// any embedded domain name lowercased, as canonical form requires.
func canonicalRDATA(rr dnsmsg.RR) ([]byte, error) {
	switch rr.Type {
	case dnsmsg.TypeA:
		ip := rr.A.To4()
		if ip == nil {
			return nil, fmt.Errorf("A record for %s has no IPv4 address", rr.Name)
		}
		return ip, nil
	case dnsmsg.TypeAAAA:
		ip := rr.AAAA.To16()
		if ip == nil {
			return nil, fmt.Errorf("AAAA record for %s has no IPv6 address", rr.Name)
		}
		return ip, nil
	case dnsmsg.TypeNS:
		return canonicalName(rr.NS)
	case dnsmsg.TypeCNAME:
		return canonicalName(rr.CNAME)
	case dnsmsg.TypeSOA:
		if rr.SOA == nil {
			return nil, fmt.Errorf("SOA record for %s has no data", rr.Name)
		}
		mname, err := canonicalName(rr.SOA.MName)
		if err != nil {
			return nil, err
		}
		rname, err := canonicalName(rr.SOA.RName)
		if err != nil {
			return nil, err
		}
		out := append(mname, rname...)
		out = append(out, uint32be(rr.SOA.Serial)...)
		out = append(out, uint32be(rr.SOA.Refresh)...)
		out = append(out, uint32be(rr.SOA.Retry)...)
		out = append(out, uint32be(rr.SOA.Expire)...)
		out = append(out, uint32be(rr.SOA.Minimum)...)
		return out, nil
	case dnsmsg.TypeMX:
		// Preference, then a name that has to be lowercased like the rest.
		if len(rr.Raw) < 2 {
			return nil, fmt.Errorf("MX record for %s is too short", rr.Name)
		}
		name, err := lowercaseWireName(rr.Raw[2:])
		if err != nil {
			return nil, err
		}
		return append(append([]byte{}, rr.Raw[:2]...), name...), nil
	case dnsmsg.TypePTR:
		return lowercaseWireName(rr.Raw)
	default:
		// Everything else is passed through: types defined after RFC 1035
		// hold no names that canonical form lowercases.
		return rr.Raw, nil
	}
}

// lowercaseWireName lowercases the labels of an uncompressed wire-format
// name in place of a copy.
func lowercaseWireName(buf []byte) ([]byte, error) {
	out := append([]byte{}, buf...)
	off := 0
	for off < len(out) {
		length := int(out[off])
		if length == 0 {
			return out[:off+1], nil
		}
		if length&0xC0 != 0 || off+1+length > len(out) {
			return nil, errors.New("malformed name in RDATA")
		}
		for i := off + 1; i < off+1+length; i++ {
			out[i] = lowerByte(out[i])
		}
		off += 1 + length
	}
	return nil, errors.New("unterminated name in RDATA")
}

// canonicalName is a domain name in wire form, uncompressed and lowercased.
func canonicalName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label in %q", name)
		}
		out = append(out, byte(len(label)))
		for i := 0; i < len(label); i++ {
			out = append(out, lowerByte(label[i]))
		}
	}
	return append(out, 0), nil
}

// lowerByte lowercases one ASCII byte. DNS case-insensitivity is defined
// over ASCII only, so this deliberately leaves everything else alone.
func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// verifySignature checks sig over data with the public key in its DNSKEY
// wire form, which differs per algorithm family.
func verifySignature(algorithm uint8, publicKey, data, sig []byte) error {
	switch algorithm {
	case algRSASHA256:
		return verifyRSA(publicKey, data, sig, crypto256)
	case algRSASHA512:
		return verifyRSA(publicKey, data, sig, crypto512)
	case algECDSAP256SHA256:
		return verifyECDSA(elliptic.P256(), publicKey, data, sig, crypto256)
	case algECDSAP384SHA384:
		return verifyECDSA(elliptic.P384(), publicKey, data, sig, crypto384)
	case algEd25519:
		if len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("Ed25519 key is %d bytes, want %d", len(publicKey), ed25519.PublicKeySize)
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), data, sig) {
			return errors.New("Ed25519 signature does not verify")
		}
		return nil
	default:
		return fmt.Errorf("%w: signature algorithm %d", ErrUnsupportedAlgorithm, algorithm)
	}
}

// hash names the digest a signature algorithm is defined over.
type hash int

const (
	crypto256 hash = iota
	crypto384
	crypto512
)

func (h hash) sum(data []byte) []byte {
	switch h {
	case crypto384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto512:
		s := sha512.Sum512(data)
		return s[:]
	default:
		s := sha256.Sum256(data)
		return s[:]
	}
}

// verifyRSA parses the DNSKEY form of an RSA key (RFC 3110): an exponent
// length, the exponent, then the modulus.
func verifyRSA(publicKey, data, sig []byte, h hash) error {
	if len(publicKey) < 3 {
		return errors.New("RSA key is too short")
	}
	expLen := int(publicKey[0])
	offset := 1
	if expLen == 0 {
		// A zero byte means the length is in the next two bytes, for
		// exponents longer than 255 bytes.
		expLen = int(publicKey[1])<<8 | int(publicKey[2])
		offset = 3
	}
	if expLen == 0 || offset+expLen >= len(publicKey) {
		return errors.New("RSA key exponent length is out of range")
	}
	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(publicKey[offset+expLen:]),
		E: int(new(big.Int).SetBytes(publicKey[offset : offset+expLen]).Int64()),
	}
	if key.E == 0 || key.N.Sign() == 0 {
		return errors.New("RSA key is malformed")
	}

	if h == crypto512 {
		return rsa.VerifyPKCS1v15(key, crypto.SHA512, h.sum(data), sig)
	}
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, h.sum(data), sig)
}

// verifyECDSA parses the DNSKEY form of an ECDSA key, which is the raw
// coordinates with no point-format prefix, and the signature, which is r
// and s concatenated rather than the usual ASN.1.
func verifyECDSA(curve elliptic.Curve, publicKey, data, sig []byte, h hash) error {
	size := (curve.Params().BitSize + 7) / 8
	if len(publicKey) != 2*size {
		return fmt.Errorf("ECDSA key is %d bytes, want %d", len(publicKey), 2*size)
	}
	if len(sig) != 2*size {
		return fmt.Errorf("ECDSA signature is %d bytes, want %d", len(sig), 2*size)
	}
	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(publicKey[:size]),
		Y:     new(big.Int).SetBytes(publicKey[size:]),
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return errors.New("ECDSA key is not a point on the curve")
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	if !ecdsa.Verify(key, h.sum(data), r, s) {
		return errors.New("ECDSA signature does not verify")
	}
	return nil
}

// VerifyDS reports whether ds is the parent's record of key: the digest of
// the key's owner name and RDATA has to match the one the parent published.
// This is the link that carries trust across a zone boundary.
func VerifyDS(owner string, key *dnsmsg.DNSKEY, ds *dnsmsg.DS) error {
	if ds.KeyTag != key.KeyTag() || ds.Algorithm != key.Algorithm {
		return errors.New("DS does not refer to this key")
	}
	name, err := canonicalName(owner)
	if err != nil {
		return err
	}
	material := append(name, keyRDATA(key)...)

	var digest []byte
	switch ds.DigestType {
	case digestSHA256:
		sum := sha256.Sum256(material)
		digest = sum[:]
	case digestSHA384:
		sum := sha512.Sum384(material)
		digest = sum[:]
	default:
		return fmt.Errorf("%w: DS digest type %d", ErrUnsupportedAlgorithm, ds.DigestType)
	}
	if !bytes.Equal(digest, ds.Digest) {
		return errors.New("DS digest does not match the key")
	}
	return nil
}

func keyRDATA(k *dnsmsg.DNSKEY) []byte {
	out := make([]byte, 4, 4+len(k.PublicKey))
	out[0] = byte(k.Flags >> 8)
	out[1] = byte(k.Flags)
	out[2] = k.Protocol
	out[3] = k.Algorithm
	return append(out, k.PublicKey...)
}

func uint16be(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func uint32be(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func splitName(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func equalName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func isSubdomainOrEqual(name, zone string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" || name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}
