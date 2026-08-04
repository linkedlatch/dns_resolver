// Package dnsmsg implements encoding and decoding of DNS wire-format
// messages as defined in RFC 1035.
package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type RRType uint16

const (
	TypeA     RRType = 1
	TypeNS    RRType = 2
	TypeCNAME RRType = 5
	TypeSOA   RRType = 6
	TypePTR   RRType = 12
	TypeMX    RRType = 15
	TypeAAAA  RRType = 28
	TypeOPT   RRType = 41 // EDNS0 pseudo-record; see edns.go
)

func (t RRType) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeAAAA:
		return "AAAA"
	case TypeOPT:
		return "OPT"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

type Class uint16

const ClassIN Class = 1

type RCode uint8

const (
	RCodeSuccess        RCode = 0
	RCodeFormatError    RCode = 1
	RCodeServerFailure  RCode = 2
	RCodeNameError      RCode = 3 // NXDOMAIN
	RCodeNotImplemented RCode = 4
	RCodeRefused        RCode = 5
)

type Header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	AD      bool // the answer was validated by this resolver (RFC 4035)
	CD      bool // the client asked for validation to be skipped
	RCode   RCode
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  RRType
	Class Class
}

// SOA holds the parsed RDATA of an SOA record: zone metadata including the
// negative-caching TTL (Minimum, per RFC 2308).
type SOA struct {
	MName   string // primary master name server for the zone
	RName   string // zone administrator's mailbox, encoded as a domain name
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

// RR is a resource record. Only the fields relevant to the record's Type
// are populated; the rest are zero values.
type RR struct {
	Name     string
	Type     RRType
	Class    Class
	TTL      uint32
	RDLength uint16

	A     net.IP // TypeA
	AAAA  net.IP // TypeAAAA
	NS    string // TypeNS
	CNAME string // TypeCNAME
	SOA   *SOA   // TypeSOA
	Raw   []byte // any other type: raw RDATA
}

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []RR
	Authorities []RR
	Additionals []RR
}

// PackQuery builds a single-question query message with RD unset, suitable
// for iterative (non-recursive) queries to authoritative servers.
func PackQuery(id uint16, name string, qtype RRType) ([]byte, error) {
	encodedName, err := encodeName(name)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 12, 12+len(encodedName)+4)
	binary.BigEndian.PutUint16(buf[0:2], id)
	// byte[2] = QR(0) Opcode(0000) AA(0) TC(0) RD(0); byte[3] = RA(0) Z(000) RCODE(0000)
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCount
	// ANCount, NSCount, ARCount left at 0

	buf = append(buf, encodedName...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(qtype))
	buf = binary.BigEndian.AppendUint16(buf, uint16(ClassIN))
	return buf, nil
}

// Pack serializes a full DNS message to wire format, compressing repeated
// domain names across the question/answer/authority/additional sections.
// Header counts are derived from the length of each section, not from
// msg.Header's count fields.
func Pack(msg *Message) ([]byte, error) {
	e := newEncoder()
	e.buf = make([]byte, 12)

	var flags1, flags2 uint8
	if msg.Header.QR {
		flags1 |= 0x80
	}
	flags1 |= (msg.Header.Opcode & 0x0F) << 3
	if msg.Header.AA {
		flags1 |= 0x04
	}
	if msg.Header.TC {
		flags1 |= 0x02
	}
	if msg.Header.RD {
		flags1 |= 0x01
	}
	if msg.Header.RA {
		flags2 |= 0x80
	}
	if msg.Header.AD {
		flags2 |= 0x20
	}
	if msg.Header.CD {
		flags2 |= 0x10
	}
	flags2 |= uint8(msg.Header.RCode) & 0x0F

	binary.BigEndian.PutUint16(e.buf[0:2], msg.Header.ID)
	e.buf[2] = flags1
	e.buf[3] = flags2
	binary.BigEndian.PutUint16(e.buf[4:6], uint16(len(msg.Questions)))
	binary.BigEndian.PutUint16(e.buf[6:8], uint16(len(msg.Answers)))
	binary.BigEndian.PutUint16(e.buf[8:10], uint16(len(msg.Authorities)))
	binary.BigEndian.PutUint16(e.buf[10:12], uint16(len(msg.Additionals)))

	for _, q := range msg.Questions {
		if err := e.writeName(q.Name); err != nil {
			return nil, err
		}
		e.writeUint16(uint16(q.Type))
		e.writeUint16(uint16(q.Class))
	}
	for _, rr := range msg.Answers {
		if err := e.writeRR(rr); err != nil {
			return nil, err
		}
	}
	for _, rr := range msg.Authorities {
		if err := e.writeRR(rr); err != nil {
			return nil, err
		}
	}
	for _, rr := range msg.Additionals {
		if err := e.writeRR(rr); err != nil {
			return nil, err
		}
	}
	return e.buf, nil
}

// Unpack parses a full DNS message from wire format.
func Unpack(buf []byte) (*Message, error) {
	d := &decoder{buf: buf}

	hdr, err := d.readHeader()
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	msg := &Message{Header: hdr}

	for i := 0; i < int(hdr.QDCount); i++ {
		q, err := d.readQuestion()
		if err != nil {
			return nil, fmt.Errorf("question %d: %w", i, err)
		}
		msg.Questions = append(msg.Questions, q)
	}
	msg.Answers, err = d.readRRs(int(hdr.ANCount))
	if err != nil {
		return nil, fmt.Errorf("answer: %w", err)
	}
	msg.Authorities, err = d.readRRs(int(hdr.NSCount))
	if err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	msg.Additionals, err = d.readRRs(int(hdr.ARCount))
	if err != nil {
		return nil, fmt.Errorf("additional: %w", err)
	}
	return msg, nil
}

// CloneRRs copies rrs deeply enough that the result shares nothing mutable
// with the original.
//
// Copying the structs alone is not enough: the address, RDATA and SOA
// fields are a slice, a slice and a pointer, so plain assignment leaves two
// records pointing at the same bytes. Anything that hands the same records
// to more than one client - a cache, a de-duplicator - has to copy them, or
// one client editing a record edits what the others were given.
func CloneRRs(rrs []RR) []RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]RR, len(rrs))
	for i, rr := range rrs {
		out[i] = rr
		out[i].A = bytes.Clone(rr.A)
		out[i].AAAA = bytes.Clone(rr.AAAA)
		out[i].Raw = bytes.Clone(rr.Raw)
		if rr.SOA != nil {
			soa := *rr.SOA
			out[i].SOA = &soa
		}
	}
	return out
}
