// Package dnsmsg implements encoding and decoding of DNS wire-format
// messages as defined in RFC 1035.
package dnsmsg

import (
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
	TypeAAAA  RRType = 28
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
	case TypeAAAA:
		return "AAAA"
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
