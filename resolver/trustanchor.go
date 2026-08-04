package resolver

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"dns_resolver/dnsmsg"
)

// rootKSK2017Digest is the SHA-256 digest of the root zone's key signing
// key with tag 20326, published by IANA as the root trust anchor.
//
// This is the one piece of DNS data that cannot be learned from DNS: every
// signature check ends here, so it has to come from somewhere else and be
// kept current out of band. IANA publishes it at
// https://data.iana.org/root-anchors/.
//
// It is compiled in as the default because a resolver has to work out of
// the box, but the built-in copy is only as fresh as the binary. A key
// rollover can be followed without rebuilding by pointing the
// trust_anchor setting at a file - see LoadTrustAnchors. Following one
// automatically, the way RFC 5011 describes, is still not done.
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

// LoadTrustAnchors reads the root's trust anchors from a file, so that a
// root key rollover can be followed by replacing a file rather than the
// binary.
//
// The file holds DS records in the ordinary presentation format, which is
// what `dig . DS` prints and what every other resolver's anchor file looks
// like:
//
//	; comments and blank lines are ignored
//	. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
//
// More than one line is normal and expected: during a rollover both the
// outgoing and incoming keys are published, and a resolver that has only
// one of them stops working the day the other takes over.
func LoadTrustAnchors(path string) ([]dnsmsg.DS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	anchors, err := ParseTrustAnchors(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return anchors, nil
}

// ParseTrustAnchors reads DS records for the root zone.
func ParseTrustAnchors(r io.Reader) ([]dnsmsg.DS, error) {
	var anchors []dnsmsg.DS
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if i := strings.IndexByte(text, ';'); i >= 0 {
			text = text[:i]
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		ds, err := parseDSLine(fields)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		anchors = append(anchors, ds)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no DS records found")
	}
	return anchors, nil
}

// parseDSLine reads one DS record. The owner name has to be the root: these
// anchors are only ever consulted for the root zone, and silently ignoring
// an anchor for something else would leave the operator believing in a
// configuration that does nothing.
func parseDSLine(fields []string) (dnsmsg.DS, error) {
	if !equalName(fields[0], ".") {
		return dnsmsg.DS{}, fmt.Errorf("owner name is %q, want the root zone \".\"", fields[0])
	}
	// Between the name and the type sit an optional TTL and class, which
	// differ between the tools that write these files and mean nothing here.
	i := slices.IndexFunc(fields, func(f string) bool { return strings.EqualFold(f, "DS") })
	if i < 0 {
		return dnsmsg.DS{}, fmt.Errorf("not a DS record")
	}
	rdata := fields[i+1:]
	if len(rdata) < 4 {
		return dnsmsg.DS{}, fmt.Errorf("DS record has %d fields, want key tag, algorithm, digest type and digest", len(rdata))
	}

	keyTag, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return dnsmsg.DS{}, fmt.Errorf("key tag %q: %w", rdata[0], err)
	}
	algorithm, err := strconv.ParseUint(rdata[1], 10, 8)
	if err != nil {
		return dnsmsg.DS{}, fmt.Errorf("algorithm %q: %w", rdata[1], err)
	}
	digestType, err := strconv.ParseUint(rdata[2], 10, 8)
	if err != nil {
		return dnsmsg.DS{}, fmt.Errorf("digest type %q: %w", rdata[2], err)
	}
	// The digest is often written in groups separated by spaces.
	digest, err := hex.DecodeString(strings.Join(rdata[3:], ""))
	if err != nil {
		return dnsmsg.DS{}, fmt.Errorf("digest: %w", err)
	}
	if len(digest) == 0 {
		return dnsmsg.DS{}, fmt.Errorf("digest is empty")
	}

	return dnsmsg.DS{
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     digest,
	}, nil
}
