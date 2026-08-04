package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DNSSEC record types (RFC 4034). They are ordinary records carrying
// signatures and keys; what makes them special is only how they are used.
const (
	TypeDS     RRType = 43
	TypeRRSIG  RRType = 46
	TypeNSEC   RRType = 47
	TypeDNSKEY RRType = 48
	TypeNSEC3  RRType = 50
)

// DNSKEY flags (RFC 4034 2.1.1).
const (
	DNSKEYFlagZoneKey = 1 << 8 // this key signs records in the zone
	DNSKEYFlagSEP     = 1      // "secure entry point": the key a DS points at
)

// DNSKEY is a public key a zone signs its records with.
type DNSKEY struct {
	Flags     uint16
	Protocol  uint8 // always 3; the field is a leftover from an earlier design
	Algorithm uint8
	PublicKey []byte
}

// RRSIG is a signature over one RRset, plus everything a verifier needs to
// know which key made it and what exactly was signed.
type RRSIG struct {
	TypeCovered RRType
	Algorithm   uint8
	Labels      uint8 // label count of the signer's idea of the owner name; wildcards signed fewer
	OriginalTTL uint32
	Expiration  uint32 // seconds since the Unix epoch, as an unsigned 32-bit wrap-around
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
}

// DS points from a parent zone at a key in the child zone, by hash. It is
// the link that makes a chain out of otherwise unrelated zone keys.
type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// NSEC proves a name does not exist, by naming the next one that does and
// listing the types the owner has.
type NSEC struct {
	NextDomain string
	TypeBitmap []byte
}

// parseDNSKEY reads DNSKEY RDATA out of a record's raw bytes.
func parseDNSKEY(raw []byte) (*DNSKEY, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("DNSKEY RDATA is %d bytes, want at least 4", len(raw))
	}
	return &DNSKEY{
		Flags:     binary.BigEndian.Uint16(raw[0:2]),
		Protocol:  raw[2],
		Algorithm: raw[3],
		PublicKey: raw[4:],
	}, nil
}

// parseDS reads DS RDATA.
func parseDS(raw []byte) (*DS, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("DS RDATA is %d bytes, want at least 4", len(raw))
	}
	return &DS{
		KeyTag:     binary.BigEndian.Uint16(raw[0:2]),
		Algorithm:  raw[2],
		DigestType: raw[3],
		Digest:     raw[4:],
	}, nil
}

// parseRRSIG reads RRSIG RDATA. The signer name is a domain name, which is
// never compressed here (RFC 4034 3.1.7), so it is read from the RDATA
// alone rather than against the whole message.
func parseRRSIG(raw []byte) (*RRSIG, error) {
	if len(raw) < 18 {
		return nil, fmt.Errorf("RRSIG RDATA is %d bytes, want at least 18", len(raw))
	}
	sig := &RRSIG{
		TypeCovered: RRType(binary.BigEndian.Uint16(raw[0:2])),
		Algorithm:   raw[2],
		Labels:      raw[3],
		OriginalTTL: binary.BigEndian.Uint32(raw[4:8]),
		Expiration:  binary.BigEndian.Uint32(raw[8:12]),
		Inception:   binary.BigEndian.Uint32(raw[12:16]),
		KeyTag:      binary.BigEndian.Uint16(raw[16:18]),
	}
	name, n, err := readUncompressedName(raw[18:])
	if err != nil {
		return nil, fmt.Errorf("RRSIG signer name: %w", err)
	}
	sig.SignerName = name
	sig.Signature = raw[18+n:]
	return sig, nil
}

func parseNSEC(raw []byte) (*NSEC, error) {
	name, n, err := readUncompressedName(raw)
	if err != nil {
		return nil, fmt.Errorf("NSEC next domain: %w", err)
	}
	return &NSEC{NextDomain: name, TypeBitmap: raw[n:]}, nil
}

// readUncompressedName decodes a domain name that cannot contain
// compression pointers, returning it and how many bytes it occupied.
func readUncompressedName(buf []byte) (string, int, error) {
	var labels []string
	off := 0
	for {
		if off >= len(buf) {
			return "", 0, fmt.Errorf("name runs past the end of the RDATA")
		}
		length := int(buf[off])
		if length == 0 {
			off++
			break
		}
		if length&0xC0 != 0 {
			return "", 0, fmt.Errorf("compressed or reserved label in RDATA")
		}
		off++
		if off+length > len(buf) {
			return "", 0, fmt.Errorf("label runs past the end of the RDATA")
		}
		labels = append(labels, string(buf[off:off+length]))
		off += length
	}
	if len(labels) == 0 {
		return ".", off, nil
	}
	return strings.Join(labels, "."), off, nil
}

// AsDNSKEY returns the parsed DNSKEY in rr, or false if it is not one.
func (rr RR) AsDNSKEY() (*DNSKEY, bool) {
	if rr.Type != TypeDNSKEY {
		return nil, false
	}
	key, err := parseDNSKEY(rr.Raw)
	return key, err == nil
}

// AsDS returns the parsed DS in rr, or false if it is not one.
func (rr RR) AsDS() (*DS, bool) {
	if rr.Type != TypeDS {
		return nil, false
	}
	ds, err := parseDS(rr.Raw)
	return ds, err == nil
}

// AsRRSIG returns the parsed RRSIG in rr, or false if it is not one.
func (rr RR) AsRRSIG() (*RRSIG, bool) {
	if rr.Type != TypeRRSIG {
		return nil, false
	}
	sig, err := parseRRSIG(rr.Raw)
	return sig, err == nil
}

// AsNSEC returns the parsed NSEC in rr, or false if it is not one.
func (rr RR) AsNSEC() (*NSEC, bool) {
	if rr.Type != TypeNSEC {
		return nil, false
	}
	nsec, err := parseNSEC(rr.Raw)
	return nsec, err == nil
}

// KeyTag computes the identifier a DS or RRSIG uses to say which key it
// means (RFC 4034 appendix B). It is a checksum, not an identity: two keys
// in a zone can share one, so a tag narrows the candidates and the
// signature check decides.
func (k *DNSKEY) KeyTag() uint16 {
	rdata := k.rdata()
	var sum uint32
	for i, b := range rdata {
		if i&1 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	sum += sum >> 16 & 0xFFFF
	return uint16(sum & 0xFFFF)
}

// rdata rebuilds the wire form of the key's RDATA, which both the key tag
// and the DS digest are computed over.
func (k *DNSKEY) rdata() []byte {
	out := make([]byte, 4, 4+len(k.PublicKey))
	binary.BigEndian.PutUint16(out[0:2], k.Flags)
	out[2] = k.Protocol
	out[3] = k.Algorithm
	return append(out, k.PublicKey...)
}

// IsZoneKey reports whether the key signs records in its zone, as opposed
// to being present for some other purpose.
func (k *DNSKEY) IsZoneKey() bool { return k.Flags&DNSKEYFlagZoneKey != 0 }

// TypeInBitmap reports whether the NSEC type bitmap (RFC 4034 4.1.2) lists
// the given type, which is how an NSEC record says what does and does not
// exist at a name.
func (n *NSEC) TypeInBitmap(t RRType) bool {
	buf := n.TypeBitmap
	for len(buf) >= 2 {
		window, length := buf[0], int(buf[1])
		if len(buf) < 2+length {
			return false
		}
		bitmap := buf[2 : 2+length]
		if uint16(window) == uint16(t)>>8 {
			offset := int(uint16(t) & 0xFF)
			if i := offset / 8; i < len(bitmap) {
				return bitmap[i]&(0x80>>(offset%8)) != 0
			}
			return false
		}
		buf = buf[2+length:]
	}
	return false
}
