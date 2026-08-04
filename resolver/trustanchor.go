package resolver

import (
	"encoding/hex"

	"dns_resolver/dnsmsg"
)

// rootKSK2017Digest is the SHA-256 digest of the root zone's key signing
// key with tag 20326, published by IANA as the root trust anchor.
//
// This is the one piece of DNS data that cannot be learned from DNS: every
// signature check ends here, so it has to be built in and kept current out
// of band. IANA publishes it at https://data.iana.org/root-anchors/, and a
// resolver that lives long enough to see a key rollover has to follow the
// automated update procedure of RFC 5011 - which this does not do, so a
// rollover means shipping a new binary.
const rootKSK2017Digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

const (
	rootKSK2017Tag     = 20326
	algorithmRSASHA256 = 8
	digestTypeSHA256   = 2
)

// RootAnchors returns the trust anchors for the root zone.
func RootAnchors() []dnsmsg.DS {
	digest, err := hex.DecodeString(rootKSK2017Digest)
	if err != nil {
		panic("resolver: built-in root trust anchor is not valid hex: " + err.Error())
	}
	return []dnsmsg.DS{{
		KeyTag:     rootKSK2017Tag,
		Algorithm:  algorithmRSASHA256,
		DigestType: digestTypeSHA256,
		Digest:     digest,
	}}
}
