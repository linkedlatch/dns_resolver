package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// maxPointerOffset is the largest byte offset a compression pointer can
// address: pointers are 14 bits (RFC 1035 4.1.4).
const maxPointerOffset = 0x3FFF

// encoder builds a DNS message, compressing repeated domain names by
// pointing back to the longest previously-written suffix of the name
// instead of repeating its labels.
type encoder struct {
	buf   []byte
	names map[string]int // lowercased dotted name -> byte offset of its first occurrence
}

func newEncoder() *encoder {
	return &encoder{names: make(map[string]int)}
}

// writeName appends name in wire format, replacing the longest suffix of it
// that was already written earlier in buf with a compression pointer.
func (e *encoder) writeName(name string) error {
	name = strings.TrimSuffix(name, ".")
	if len(name) > maxNameLength {
		return fmt.Errorf("name too long: %q", name)
	}
	var labels []string
	if name != "" {
		labels = strings.Split(name, ".")
	}

	for i := 0; i < len(labels); i++ {
		suffix := strings.ToLower(strings.Join(labels[i:], "."))
		offset, ok := e.names[suffix]
		if !ok {
			continue
		}
		for _, label := range labels[:i] {
			if len(label) == 0 || len(label) > maxLabelLength {
				return fmt.Errorf("invalid label %q in name %q", label, name)
			}
			e.buf = append(e.buf, byte(len(label)))
			e.buf = append(e.buf, label...)
		}
		e.buf = append(e.buf, byte(0xC0|(offset>>8)), byte(offset))
		return nil
	}

	for i, label := range labels {
		if len(label) == 0 || len(label) > maxLabelLength {
			return fmt.Errorf("invalid label %q in name %q", label, name)
		}
		suffix := strings.ToLower(strings.Join(labels[i:], "."))
		if _, exists := e.names[suffix]; !exists && len(e.buf) <= maxPointerOffset {
			e.names[suffix] = len(e.buf)
		}
		e.buf = append(e.buf, byte(len(label)))
		e.buf = append(e.buf, label...)
	}
	e.buf = append(e.buf, 0)
	return nil
}

func (e *encoder) writeUint16(v uint16) {
	e.buf = binary.BigEndian.AppendUint16(e.buf, v)
}

func (e *encoder) writeUint32(v uint32) {
	e.buf = binary.BigEndian.AppendUint32(e.buf, v)
}

func (e *encoder) writeRR(rr RR) error {
	if err := e.writeName(rr.Name); err != nil {
		return err
	}
	e.writeUint16(uint16(rr.Type))
	e.writeUint16(uint16(rr.Class))
	e.writeUint32(rr.TTL)

	rdlenOffset := len(e.buf)
	e.writeUint16(0) // placeholder, patched below once RDATA is known
	rdataStart := len(e.buf)

	switch rr.Type {
	case TypeA:
		ip := rr.A.To4()
		if ip == nil {
			return fmt.Errorf("A record for %q has no valid IPv4 address", rr.Name)
		}
		e.buf = append(e.buf, ip...)
	case TypeAAAA:
		ip := rr.AAAA.To16()
		if ip == nil {
			return fmt.Errorf("AAAA record for %q has no valid IPv6 address", rr.Name)
		}
		e.buf = append(e.buf, ip...)
	case TypeNS:
		if err := e.writeName(rr.NS); err != nil {
			return err
		}
	case TypeCNAME:
		if err := e.writeName(rr.CNAME); err != nil {
			return err
		}
	default:
		e.buf = append(e.buf, rr.Raw...)
	}

	rdlen := len(e.buf) - rdataStart
	binary.BigEndian.PutUint16(e.buf[rdlenOffset:rdlenOffset+2], uint16(rdlen))
	return nil
}
