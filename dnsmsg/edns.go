package dnsmsg

// EDNS0 (RFC 6891) extends the fixed 1987 message format without changing
// it, by carrying an OPT pseudo-record in the additional section. OPT is
// not a real resource record: its NAME is always the root, and the CLASS
// and TTL fields are repurposed to hold the sender's UDP payload size and
// a set of flags/version bits respectively. The accessors here exist so
// callers never have to remember that reinterpretation.

// DefaultUDPSize is the UDP payload size we advertise. 1232 is the DNS
// Flag Day 2020 recommendation: it keeps responses under the smallest
// plausible path MTU (1280 for IPv6, minus headers), avoiding IP
// fragmentation, which is both unreliable and a spoofing aid.
const DefaultUDPSize uint16 = 1232

// ednsDOBit is the "DNSSEC OK" flag within the OPT record's TTL field.
// Authoritative servers commonly omit DNSSEC records unless it is set.
const ednsDOBit uint32 = 0x8000

// RCodeBadVers is an extended RCODE, i.e. one that does not fit in the
// header's 4 bits and is only expressible via OPT. Servers return it when
// they do not support the EDNS version we asked for.
const RCodeBadVers uint16 = 16

// NewOPT builds an OPT pseudo-record advertising udpSize as the largest
// UDP response we can accept, optionally requesting DNSSEC records.
func NewOPT(udpSize uint16, do bool) RR {
	rr := RR{
		Name:  ".",
		Type:  TypeOPT,
		Class: Class(udpSize), // OPT repurposes CLASS as the UDP payload size
	}
	if do {
		rr.TTL = ednsDOBit // OPT repurposes TTL as extended-rcode/version/flags
	}
	return rr
}

// UDPSize returns the UDP payload size advertised by an OPT record.
func (rr RR) UDPSize() uint16 { return uint16(rr.Class) }

// DO reports whether an OPT record has the DNSSEC OK bit set.
func (rr RR) DO() bool { return rr.TTL&ednsDOBit != 0 }

// OPT returns the message's OPT pseudo-record, or nil if it has none (i.e.
// the sender did not use EDNS0).
func (m *Message) OPT() *RR {
	for i := range m.Additionals {
		if m.Additionals[i].Type == TypeOPT {
			return &m.Additionals[i]
		}
	}
	return nil
}

// ExtendedRCode returns the full 12-bit response code, combining the 4 bits
// in the header with the upper 8 bits an OPT record may carry.
func (m *Message) ExtendedRCode() uint16 {
	rcode := uint16(m.Header.RCode)
	if opt := m.OPT(); opt != nil {
		rcode |= uint16(opt.TTL>>24) << 4
	}
	return rcode
}

// PackQueryEDNS0 builds a single-question query like PackQuery, but with an
// OPT record announcing EDNS0 support. Advertising a larger UDP payload
// size lets servers reply in one datagram instead of setting TC and forcing
// a second round trip over TCP.
func PackQueryEDNS0(id uint16, name string, qtype RRType, udpSize uint16, do bool) ([]byte, error) {
	return Pack(&Message{
		Header:      Header{ID: id},
		Questions:   []Question{{Name: name, Type: qtype, Class: ClassIN}},
		Additionals: []RR{NewOPT(udpSize, do)},
	})
}
