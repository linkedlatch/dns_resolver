// Package resolver implements iterative (non-recursive-request) DNS
// resolution: starting from the root servers, it follows NS referrals down
// to the authoritative server for a name, the same way `dig +trace` does.
package resolver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

// ErrNXDOMAIN indicates the queried name does not exist. Callers that need
// to distinguish this from other resolution failures (e.g. a server mapping
// it to RCODE 3) should check with errors.Is, not by matching error text.
var ErrNXDOMAIN = errors.New("NXDOMAIN")

type Resolver struct{}

func New() *Resolver { return &Resolver{} }

// Resolve performs iterative resolution of qname/qtype starting from the
// root servers and returns the resulting A/AAAA addresses, following any
// CNAME chain along the way.
func (r *Resolver) Resolve(qname string, qtype dnsmsg.RRType) ([]net.IP, error) {
	rrs, err := r.ResolveRR(qname, qtype)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(rrs))
	for _, rr := range rrs {
		switch qtype {
		case dnsmsg.TypeA:
			ips = append(ips, rr.A)
		case dnsmsg.TypeAAAA:
			ips = append(ips, rr.AAAA)
		}
	}
	return ips, nil
}

// ResolveRR performs iterative resolution like Resolve, but returns the
// matching resource records themselves (preserving TTL) instead of just
// their addresses. A DNS server answering client queries needs the TTL to
// report accurate values (and, later, to drive cache expiry).
func (r *Resolver) ResolveRR(qname string, qtype dnsmsg.RRType) ([]dnsmsg.RR, error) {
	return r.resolve(qname, qtype, 0, 0)
}

func (r *Resolver) resolve(qname string, qtype dnsmsg.RRType, cnameDepth, glueDepth int) ([]dnsmsg.RR, error) {
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
			return nil, fmt.Errorf("%w: %s", ErrNXDOMAIN, qname)
		}
		if resp.Header.RCode != dnsmsg.RCodeSuccess {
			return nil, fmt.Errorf("%s answered %s query for %s with RCODE %d", server, qtype, qname, resp.Header.RCode)
		}

		// Follow any CNAME chain as far as this single response allows
		// before falling back to a fresh iterative lookup for the
		// remainder: servers commonly bundle the whole chain plus the
		// final answer together in one response.
		name := qname
		var answers []dnsmsg.RR
		hops := 0
		for {
			var cnameTarget string
			for _, rr := range resp.Answers {
				if !equalName(rr.Name, name) {
					continue
				}
				switch {
				case rr.Type == qtype && qtype == dnsmsg.TypeA && rr.A != nil:
					answers = append(answers, rr)
				case rr.Type == qtype && qtype == dnsmsg.TypeAAAA && rr.AAAA != nil:
					answers = append(answers, rr)
				case rr.Type == dnsmsg.TypeCNAME:
					cnameTarget = rr.CNAME
				}
			}
			if len(answers) > 0 || cnameTarget == "" {
				break
			}
			hops++
			if cnameDepth+hops >= maxCNAMEChain {
				return nil, fmt.Errorf("CNAME chain too long starting at %s", qname)
			}
			name = cnameTarget
		}

		if len(answers) > 0 {
			return answers, nil
		}
		if name != qname {
			return r.resolve(name, qtype, cnameDepth+hops, glueDepth)
		}
		if len(resp.Answers) > 0 {
			return nil, fmt.Errorf("no %s record for %s (other records present)", qtype, qname)
		}

		// No direct answer: look for a referral to more authoritative
		// servers. Only trust NS delegations that are in-bailiwick for
		// qname (i.e. for qname itself or one of its ancestor zones), so
		// a malicious or compromised authoritative server can't redirect
		// resolution for an unrelated zone by stuffing extra NS records
		// into the authority section.
		nsNames := make(map[string]bool)
		for _, rr := range resp.Authorities {
			if rr.Type == dnsmsg.TypeNS && isSubdomainOrEqual(qname, rr.Name) {
				nsNames[strings.ToLower(rr.NS)] = true
			}
		}
		if len(nsNames) == 0 {
			return nil, fmt.Errorf("no answer and no referral for %s from %s", qname, server)
		}

		var newServers []net.IP
		for _, rr := range resp.Additionals {
			if !nsNames[strings.ToLower(rr.Name)] {
				continue
			}
			switch {
			case rr.Type == dnsmsg.TypeA && rr.A != nil:
				newServers = append(newServers, rr.A)
			case rr.Type == dnsmsg.TypeAAAA && rr.AAAA != nil:
				newServers = append(newServers, rr.AAAA)
			}
		}

		if len(newServers) == 0 {
			if glueDepth >= maxGlueLookups {
				return nil, fmt.Errorf("referral for %s has no glue and glue lookup depth exceeded", qname)
			}
			for ns := range nsNames {
				glueRRs, err := r.resolve(ns, dnsmsg.TypeA, 0, glueDepth+1)
				if err != nil || len(glueRRs) == 0 {
					continue
				}
				for _, rr := range glueRRs {
					newServers = append(newServers, rr.A)
				}
				break
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
	id, err := randomQueryID()
	if err != nil {
		return nil, fmt.Errorf("generate query ID: %w", err)
	}
	packet, err := dnsmsg.PackQuery(id, qname, qtype)
	if err != nil {
		return nil, err
	}

	msg, err := queryUDP(server, packet, id, qname, qtype)
	if err != nil {
		return nil, err
	}
	if msg.Header.TC {
		msg, err = queryTCP(server, packet, id, qname, qtype)
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// randomQueryID uses crypto/rand rather than math/rand: the query ID is a
// core defense against cache-poisoning (an off-path attacker guessing it
// lets them forge an accepted answer), so it must not be predictable.
func randomQueryID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func queryUDP(server net.IP, packet []byte, id uint16, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, error) {
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
	return unpackAndVerify(buf[:n], id, qname, qtype)
}

func queryTCP(server net.IP, packet []byte, id uint16, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, error) {
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
	return unpackAndVerify(buf, id, qname, qtype)
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

// unpackAndVerify parses buf and checks that it actually answers the query
// we sent: matching ID alone isn't enough, since a 16-bit ID is guessable
// by an off-path attacker racing the real server's reply. QR and the
// echoed question are cheap additional checks against spoofed or
// misdirected responses.
func unpackAndVerify(buf []byte, wantID uint16, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, error) {
	msg, err := dnsmsg.Unpack(buf)
	if err != nil {
		return nil, err
	}
	if msg.Header.ID != wantID {
		return nil, fmt.Errorf("response ID %d does not match query ID %d", msg.Header.ID, wantID)
	}
	if !msg.Header.QR {
		return nil, fmt.Errorf("message has QR=0 (not a response)")
	}
	if len(msg.Questions) != 1 || !equalName(msg.Questions[0].Name, qname) || msg.Questions[0].Type != qtype {
		return nil, fmt.Errorf("response question section does not match query for %s %s", qname, qtype)
	}
	return msg, nil
}

// equalName compares domain names ignoring case and a trailing root dot.
func equalName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// isSubdomainOrEqual reports whether name is zone itself or a subdomain of
// zone, matching on whole labels (not string suffix). Used to enforce
// bailiwick: a server answering for one zone must not be trusted to
// delegate an unrelated zone via extra records slipped into its response.
func isSubdomainOrEqual(name, zone string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" {
		return true // the root zone is an ancestor of everything
	}
	if name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}
