// Package resolver implements iterative (non-recursive-request) DNS
// resolution: starting from the root servers, it follows NS referrals down
// to the authoritative server for a name, the same way `dig +trace` does.
package resolver

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"dns_resolver/dnsmsg"
)

const (
	maxReferrals   = 30 // guards against referral loops between misconfigured servers
	maxCNAMEChain  = 15
	maxGlueLookups = 6 // caps recursive lookups for NS addresses missing glue
	queryTimeout   = 3 * time.Second
	udpReadBufSize = 4096
)

type Resolver struct{}

func New() *Resolver { return &Resolver{} }

// Resolve performs iterative resolution of qname/qtype starting from the
// root servers and returns the resulting A/AAAA addresses, following any
// CNAME chain along the way.
func (r *Resolver) Resolve(qname string, qtype dnsmsg.RRType) ([]net.IP, error) {
	return r.resolve(qname, qtype, 0, 0)
}

func (r *Resolver) resolve(qname string, qtype dnsmsg.RRType, cnameDepth, glueDepth int) ([]net.IP, error) {
	servers := RootServers

	for referrals := 0; ; referrals++ {
		if referrals >= maxReferrals {
			return nil, fmt.Errorf("too many referrals resolving %s", qname)
		}

		resp, server, err := r.queryServers(servers, qname, qtype)
		if err != nil {
			return nil, err
		}

		if resp.Header.RCode == dnsmsg.RCodeNameError {
			return nil, fmt.Errorf("NXDOMAIN: %s", qname)
		}
		if resp.Header.RCode != dnsmsg.RCodeSuccess {
			return nil, fmt.Errorf("%s answered %s query for %s with RCODE %d", server, qtype, qname, resp.Header.RCode)
		}

		var ips []net.IP
		var cname string
		for _, rr := range resp.Answers {
			if !strings.EqualFold(rr.Name, qname) {
				continue
			}
			switch {
			case rr.Type == qtype && qtype == dnsmsg.TypeA && rr.A != nil:
				ips = append(ips, rr.A)
			case rr.Type == qtype && qtype == dnsmsg.TypeAAAA && rr.AAAA != nil:
				ips = append(ips, rr.AAAA)
			case rr.Type == dnsmsg.TypeCNAME:
				cname = rr.CNAME
			}
		}

		if len(ips) > 0 {
			return ips, nil
		}
		if cname != "" {
			if cnameDepth >= maxCNAMEChain {
				return nil, fmt.Errorf("CNAME chain too long starting at %s", qname)
			}
			return r.resolve(cname, qtype, cnameDepth+1, glueDepth)
		}
		if len(resp.Answers) > 0 {
			return nil, fmt.Errorf("no %s record for %s (other records present)", qtype, qname)
		}

		// No direct answer: look for a referral to more authoritative servers.
		nsNames := make(map[string]bool)
		for _, rr := range resp.Authorities {
			if rr.Type == dnsmsg.TypeNS {
				nsNames[strings.ToLower(rr.NS)] = true
			}
		}
		if len(nsNames) == 0 {
			return nil, fmt.Errorf("no answer and no referral for %s from %s", qname, server)
		}

		var newServers []net.IP
		for _, rr := range resp.Additionals {
			if rr.Type == dnsmsg.TypeA && rr.A != nil && nsNames[strings.ToLower(rr.Name)] {
				newServers = append(newServers, rr.A)
			}
		}

		if len(newServers) == 0 {
			if glueDepth >= maxGlueLookups {
				return nil, fmt.Errorf("referral for %s has no glue and glue lookup depth exceeded", qname)
			}
			for ns := range nsNames {
				ips, err := r.resolve(ns, dnsmsg.TypeA, 0, glueDepth+1)
				if err == nil && len(ips) > 0 {
					newServers = ips
					break
				}
			}
		}
		if len(newServers) == 0 {
			return nil, fmt.Errorf("could not resolve any name server address for delegation of %s", qname)
		}

		servers = newServers
	}
}

// queryServers tries each server in turn until one answers.
func (r *Resolver) queryServers(servers []net.IP, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, net.IP, error) {
	var lastErr error
	for _, s := range servers {
		msg, err := r.query(s, qname, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		return msg, s, nil
	}
	return nil, nil, fmt.Errorf("all %d server(s) failed, last error: %w", len(servers), lastErr)
}

func (r *Resolver) query(server net.IP, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, error) {
	id := uint16(rand.Intn(1 << 16))
	packet, err := dnsmsg.PackQuery(id, qname, qtype)
	if err != nil {
		return nil, err
	}

	msg, err := queryUDP(server, packet, id)
	if err != nil {
		return nil, err
	}
	if msg.Header.TC {
		msg, err = queryTCP(server, packet, id)
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func queryUDP(server net.IP, packet []byte, id uint16) (*dnsmsg.Message, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(server.String(), "53"), queryTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(queryTimeout))

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, udpReadBufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return unpackAndVerify(buf[:n], id)
}

func queryTCP(server net.IP, packet []byte, id uint16) (*dnsmsg.Message, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server.String(), "53"), queryTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(queryTimeout))

	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(packet)))
	if _, err := conn.Write(append(lenPrefix, packet...)); err != nil {
		return nil, err
	}

	var respLenBuf [2]byte
	if _, err := readFull(conn, respLenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(respLenBuf[:])
	buf := make([]byte, respLen)
	if _, err := readFull(conn, buf); err != nil {
		return nil, err
	}
	return unpackAndVerify(buf, id)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func unpackAndVerify(buf []byte, wantID uint16) (*dnsmsg.Message, error) {
	msg, err := dnsmsg.Unpack(buf)
	if err != nil {
		return nil, err
	}
	if msg.Header.ID != wantID {
		return nil, fmt.Errorf("response ID %d does not match query ID %d", msg.Header.ID, wantID)
	}
	return msg, nil
}
