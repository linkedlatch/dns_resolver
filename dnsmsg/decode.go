package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const maxCompressionPointerJumps = 20

// maxRRPrealloc bounds how large a slice we'll preallocate based on a
// record count taken from an untrusted message header. Without this, a
// 12-byte packet claiming ANCOUNT=65535 forces a large upfront allocation
// before a single byte of it is validated. append() still grows the slice
// correctly if a message legitimately has more records than this.
const maxRRPrealloc = 64

// decoder reads sequential fields out of a DNS message buffer, tracking an
// offset. Name decoding may jump around the buffer to follow compression
// pointers (RFC 1035 4.1.4), which is why the whole message must stay
// available rather than being consumed as a stream.
type decoder struct {
	buf []byte
	off int
}

func (d *decoder) readUint8() (uint8, error) {
	if d.off+1 > len(d.buf) {
		return 0, fmt.Errorf("buffer underrun reading uint8 at offset %d", d.off)
	}
	v := d.buf[d.off]
	d.off++
	return v, nil
}

func (d *decoder) readUint16() (uint16, error) {
	if d.off+2 > len(d.buf) {
		return 0, fmt.Errorf("buffer underrun reading uint16 at offset %d", d.off)
	}
	v := binary.BigEndian.Uint16(d.buf[d.off : d.off+2])
	d.off += 2
	return v, nil
}

func (d *decoder) readUint32() (uint32, error) {
	if d.off+4 > len(d.buf) {
		return 0, fmt.Errorf("buffer underrun reading uint32 at offset %d", d.off)
	}
	v := binary.BigEndian.Uint32(d.buf[d.off : d.off+4])
	d.off += 4
	return v, nil
}

func (d *decoder) readBytes(n int) ([]byte, error) {
	if d.off+n > len(d.buf) {
		return nil, fmt.Errorf("buffer underrun reading %d bytes at offset %d", n, d.off)
	}
	v := d.buf[d.off : d.off+n]
	d.off += n
	return v, nil
}

// readName decodes a (possibly compressed) domain name starting at the
// current offset. Compression pointers are absolute offsets into the full
// message, so they are resolved against d.buf rather than a local slice.
func (d *decoder) readName() (string, error) {
	var labels []string
	pos := d.off
	jumped := false
	jumps := 0
	nameLen := 0

	for {
		if pos >= len(d.buf) {
			return "", fmt.Errorf("buffer underrun reading name at offset %d", pos)
		}
		length := d.buf[pos]

		if length == 0 {
			pos++
			break
		}

		if length&0xC0 == 0xC0 {
			if pos+2 > len(d.buf) {
				return "", fmt.Errorf("buffer underrun reading compression pointer at offset %d", pos)
			}
			ptr := int(binary.BigEndian.Uint16(d.buf[pos:pos+2]) & 0x3FFF)
			if !jumped {
				d.off = pos + 2
				jumped = true
			}
			jumps++
			if jumps > maxCompressionPointerJumps {
				return "", fmt.Errorf("too many compression pointer jumps")
			}
			pos = ptr
			continue
		}

		if length&0xC0 != 0 {
			return "", fmt.Errorf("invalid label length byte 0x%02x at offset %d", length, pos)
		}

		pos++
		if pos+int(length) > len(d.buf) {
			return "", fmt.Errorf("label overruns buffer at offset %d", pos)
		}
		nameLen += int(length) + 1
		if nameLen > maxNameLength {
			return "", fmt.Errorf("name exceeds maximum length of %d bytes", maxNameLength)
		}
		labels = append(labels, string(d.buf[pos:pos+int(length)]))
		pos += int(length)
	}

	if !jumped {
		d.off = pos
	}
	if len(labels) == 0 {
		return ".", nil
	}
	return strings.Join(labels, "."), nil
}

func (d *decoder) readHeader() (Header, error) {
	var h Header
	id, err := d.readUint16()
	if err != nil {
		return h, err
	}
	flags1, err := d.readUint8()
	if err != nil {
		return h, err
	}
	flags2, err := d.readUint8()
	if err != nil {
		return h, err
	}
	qd, err := d.readUint16()
	if err != nil {
		return h, err
	}
	an, err := d.readUint16()
	if err != nil {
		return h, err
	}
	ns, err := d.readUint16()
	if err != nil {
		return h, err
	}
	ar, err := d.readUint16()
	if err != nil {
		return h, err
	}

	h.ID = id
	h.QR = flags1&0x80 != 0
	h.Opcode = (flags1 >> 3) & 0x0F
	h.AA = flags1&0x04 != 0
	h.TC = flags1&0x02 != 0
	h.RD = flags1&0x01 != 0
	h.RA = flags2&0x80 != 0
	h.RCode = RCode(flags2 & 0x0F)
	h.QDCount = qd
	h.ANCount = an
	h.NSCount = ns
	h.ARCount = ar
	return h, nil
}

func (d *decoder) readQuestion() (Question, error) {
	var q Question
	name, err := d.readName()
	if err != nil {
		return q, err
	}
	typ, err := d.readUint16()
	if err != nil {
		return q, err
	}
	class, err := d.readUint16()
	if err != nil {
		return q, err
	}
	q.Name = name
	q.Type = RRType(typ)
	q.Class = Class(class)
	return q, nil
}

func (d *decoder) readSOA() (*SOA, error) {
	mname, err := d.readName()
	if err != nil {
		return nil, err
	}
	rname, err := d.readName()
	if err != nil {
		return nil, err
	}
	serial, err := d.readUint32()
	if err != nil {
		return nil, err
	}
	refresh, err := d.readUint32()
	if err != nil {
		return nil, err
	}
	retry, err := d.readUint32()
	if err != nil {
		return nil, err
	}
	expire, err := d.readUint32()
	if err != nil {
		return nil, err
	}
	minimum, err := d.readUint32()
	if err != nil {
		return nil, err
	}
	return &SOA{
		MName:   mname,
		RName:   rname,
		Serial:  serial,
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minimum: minimum,
	}, nil
}

func (d *decoder) readRRs(count int) ([]RR, error) {
	prealloc := count
	if prealloc > maxRRPrealloc {
		prealloc = maxRRPrealloc
	}
	rrs := make([]RR, 0, prealloc)
	for i := 0; i < count; i++ {
		rr, err := d.readRR()
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		rrs = append(rrs, rr)
	}
	return rrs, nil
}

func (d *decoder) readRR() (RR, error) {
	var rr RR
	name, err := d.readName()
	if err != nil {
		return rr, err
	}
	typ, err := d.readUint16()
	if err != nil {
		return rr, err
	}
	class, err := d.readUint16()
	if err != nil {
		return rr, err
	}
	ttl, err := d.readUint32()
	if err != nil {
		return rr, err
	}
	rdlen, err := d.readUint16()
	if err != nil {
		return rr, err
	}

	rr.Name = name
	rr.Type = RRType(typ)
	rr.Class = Class(class)
	rr.TTL = ttl
	rr.RDLength = rdlen

	rdataStart := d.off
	switch rr.Type {
	case TypeA:
		if rdlen != 4 {
			return rr, fmt.Errorf("A record has RDLENGTH %d, want 4", rdlen)
		}
		b, err := d.readBytes(4)
		if err != nil {
			return rr, err
		}
		rr.A = append([]byte(nil), b...)
	case TypeAAAA:
		if rdlen != 16 {
			return rr, fmt.Errorf("AAAA record has RDLENGTH %d, want 16", rdlen)
		}
		b, err := d.readBytes(16)
		if err != nil {
			return rr, err
		}
		rr.AAAA = append([]byte(nil), b...)
	case TypeNS:
		n, err := d.readName()
		if err != nil {
			return rr, err
		}
		rr.NS = n
	case TypeCNAME:
		n, err := d.readName()
		if err != nil {
			return rr, err
		}
		rr.CNAME = n
	case TypeSOA:
		soa, err := d.readSOA()
		if err != nil {
			return rr, err
		}
		rr.SOA = soa
	default:
		b, err := d.readBytes(int(rdlen))
		if err != nil {
			return rr, err
		}
		rr.Raw = append([]byte(nil), b...)
	}

	if d.off != rdataStart+int(rdlen) {
		return rr, fmt.Errorf("RDATA for type %s consumed %d bytes, RDLENGTH said %d", rr.Type, d.off-rdataStart, rdlen)
	}
	return rr, nil
}
