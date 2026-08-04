package resolver

import (
	"crypto/rand"
	"strings"
)

// minimizedQName is the name to ask a server that is authoritative for
// zone, when what we ultimately want is qname (RFC 9156).
//
// Sending the whole name to every server on the way down tells each of them
// more than it needs: a root server learns that someone looked up
// "intranet.finance.example.com" when all it can answer is where com
// lives. Asking only one label deeper than the zone we are talking to keeps
// the rest of the name from servers that have no business seeing it.
//
// The reply to the shorter name is either a referral, which is what we
// wanted, or an answer, which tells us the delegation ends here and the
// full name can be asked of this same server.
func minimizedQName(qname, zone string) string {
	full := labelsOf(qname)
	inZone := labelsOf(zone)
	if len(full) <= len(inZone) {
		return qname
	}
	// One label below the zone: the next delegation point, if there is one.
	next := full[len(full)-len(inZone)-1:]
	return strings.Join(next, ".")
}

func labelsOf(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// randomizeCase applies 0x20 encoding: the case of a queried name is
// meaningless to a server, which must echo the question back exactly as it
// arrived, so scattering it through the name hides a few extra bits of
// entropy in every query (draft-vixie-dnsext-dns0x20).
//
// It matters because the query ID is only 16 bits. An off-path attacker
// forging a reply has to guess the ID, the source port and now the exact
// pattern of upper and lower case, and gets one try before the real answer
// arrives.
func randomizeCase(name string) string {
	letters := 0
	for i := 0; i < len(name); i++ {
		if isASCIILetter(name[i]) {
			letters++
		}
	}
	if letters == 0 {
		return name
	}

	bits := make([]byte, (letters+7)/8)
	if _, err := rand.Read(bits); err != nil {
		return name // without randomness the query is still correct, just plainer
	}

	out := []byte(name)
	n := 0
	for i := 0; i < len(out); i++ {
		if !isASCIILetter(out[i]) {
			continue
		}
		if bits[n/8]&(1<<(n%8)) != 0 {
			out[i] = toUpper(out[i])
		} else {
			out[i] = toLower(out[i])
		}
		n++
	}
	return string(out)
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func toUpper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - ('a' - 'A')
	}
	return b
}

func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
