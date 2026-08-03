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

	defaultUpstreamPort = "53"
)

// ErrNXDOMAIN indicates the queried name does not exist. Callers that need
// to distinguish this from other resolution failures (e.g. a server mapping
// it to RCODE 3) should check with errors.Is, not by matching error text.
var ErrNXDOMAIN = errors.New("NXDOMAIN")

// NXDOMAINError is returned when a name doesn't exist. It carries the SOA
// record from the authority section (when the authoritative server sent
// one), which callers doing negative caching need for the correct TTL
// (RFC 2308: min(SOA.TTL, SOA.Minimum)).
type NXDOMAINError struct {
	Name string
	SOA  *dnsmsg.RR // nil if the response had no SOA in its authority section
}

func (e *NXDOMAINError) Error() string { return fmt.Sprintf("NXDOMAIN: %s", e.Name) }

// Is lets errors.Is(err, ErrNXDOMAIN) work for callers that only care
// whether the name exists, without needing the SOA.
func (e *NXDOMAINError) Is(target error) bool { return target == ErrNXDOMAIN }

func newNXDOMAINError(qname string, authorities []dnsmsg.RR) *NXDOMAINError {
	for i := range authorities {
		if authorities[i].Type == dnsmsg.TypeSOA && authorities[i].SOA != nil {
			return &NXDOMAINError{Name: qname, SOA: &authorities[i]}
		}
	}
	return &NXDOMAINError{Name: qname}
}

// soaAuthority returns the authority section's SOA record, if it has one,
// as the authority section of a NODATA answer. Callers need it to derive
// the negative-caching TTL (RFC 2308) the same way they do for NXDOMAIN.
func soaAuthority(authorities []dnsmsg.RR) []dnsmsg.RR {
	for _, rr := range authorities {
		if rr.Type == dnsmsg.TypeSOA && rr.SOA != nil {
			return []dnsmsg.RR{rr}
		}
	}
	return nil
}

// Resolver performs iterative DNS resolution starting from the root
// servers. It holds no state, so a single Resolver is safe for concurrent
// use by multiple goroutines.
//
// Both fields exist so tests can aim resolution at a local fake
// authoritative server rather than the real internet; the zero value
// queries the real root servers on the standard port.
type Resolver struct {
	roots        []net.IP // nil: the built-in root hints
	port         string   // "": defaultUpstreamPort
	allowPrivate bool     // permit querying loopback and private addresses
}

// New returns a Resolver that starts every resolution at the root servers.
func New() *Resolver { return &Resolver{} }

func (r *Resolver) rootServers() []net.IP {
	if r.roots == nil {
		return RootServers
	}
	return r.roots
}

func (r *Resolver) upstreamPort() string {
	if r.port == "" {
		return defaultUpstreamPort
	}
	return r.port
}

// Result is what a successful resolution produced.
//
// Answers holds the records a client should receive in the answer section:
// the CNAME records traversed on the way to the name that finally held
// data, in order, followed by the records of the requested type. A NODATA
// result (the name exists but has no records of that type, RFC 2308) has no
// record of the requested type, and Authority carries the zone's SOA when
// the authoritative server sent one.
type Result struct {
	Answers   []dnsmsg.RR
	Authority []dnsmsg.RR
}

// Resolve performs iterative resolution of qname/qtype starting from the
// root servers and returns the resulting A/AAAA addresses, following any
// CNAME chain along the way.
func (r *Resolver) Resolve(qname string, qtype dnsmsg.RRType) ([]net.IP, error) {
	res, err := r.ResolveRR(qname, qtype)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(res.Answers))
	for _, rr := range res.Answers {
		// Answers may also contain the CNAME records leading to the
		// addresses; a caller after plain IPs only wants the addresses.
		switch {
		case rr.Type == dnsmsg.TypeA && rr.A != nil:
			ips = append(ips, rr.A)
		case rr.Type == dnsmsg.TypeAAAA && rr.AAAA != nil:
			ips = append(ips, rr.AAAA)
		}
	}
	return ips, nil
}

// ResolveRR performs iterative resolution like Resolve, but returns the
// resource records themselves (preserving TTL) instead of just their
// addresses. A DNS server answering client queries needs the TTL to report
// accurate values (and, later, to drive cache expiry), and needs the CNAME
// chain and NODATA SOA that Result carries to build a correct response.
func (r *Resolver) ResolveRR(qname string, qtype dnsmsg.RRType) (Result, error) {
	return r.resolve(qname, qtype, 0, 0)
}

func (r *Resolver) resolve(qname string, qtype dnsmsg.RRType, cnameDepth, glueDepth int) (Result, error) {
	servers := r.rootServers()
	// zone is what the servers we are currently talking to are authoritative
	// for. It bounds what their answers are allowed to affect: a referral
	// has to lead strictly below it, and glue has to be a name inside it.
	zone := "."

	for referrals := 0; ; referrals++ {
		if referrals >= maxReferrals {
			return Result{}, fmt.Errorf("too many referrals resolving %s", qname)
		}

		resp, server, err := r.queryServers(servers, qname, qtype)
		if err != nil {
			return Result{}, err
		}

		if resp.Header.RCode == dnsmsg.RCodeNameError {
			return Result{}, newNXDOMAINError(qname, resp.Authorities)
		}
		if resp.Header.RCode != dnsmsg.RCodeSuccess {
			return Result{}, fmt.Errorf("%s answered %s query for %s with RCODE %d", server, qtype, qname, resp.Header.RCode)
		}

		// Follow any CNAME chain as far as this single response allows
		// before falling back to a fresh iterative lookup for the
		// remainder: servers commonly bundle the whole chain plus the
		// final answer together in one response.
		//
		// The CNAME records traversed are part of the answer, not just an
		// internal step: a stub resolver discards any record it cannot
		// reach from the question name by following the chain, so an
		// answer stripped of its CNAMEs looks like it belongs to a
		// different question and is thrown away.
		name := qname
		var chain, answers []dnsmsg.RR
		for {
			var cname *dnsmsg.RR
			for i, rr := range resp.Answers {
				if !equalName(rr.Name, name) || rr.Class != dnsmsg.ClassIN {
					continue
				}
				switch {
				case rr.Type == qtype:
					// Matching on qtype alone (rather than a per-type case)
					// is what lets MX, TXT, SRV and the rest resolve: the
					// decoder preserves unparsed RDATA and the encoder
					// writes it back out. It also handles a CNAME query
					// itself, which must answer with the CNAME rather than
					// follow it.
					answers = append(answers, rr)
				case rr.Type == dnsmsg.TypeCNAME:
					cname = &resp.Answers[i]
				}
			}
			if len(answers) > 0 || cname == nil {
				break
			}
			if cnameDepth+len(chain)+1 >= maxCNAMEChain {
				return Result{}, fmt.Errorf("CNAME chain too long starting at %s", qname)
			}
			chain = append(chain, *cname)
			name = cname.CNAME
		}

		if len(answers) > 0 {
			return Result{Answers: append(chain, answers...)}, nil
		}
		if name != qname {
			// The chain left what this server knows about; resolve the
			// rest from the root, keeping the CNAMEs collected so far in
			// front of whatever it finds.
			res, err := r.resolve(name, qtype, cnameDepth+len(chain), glueDepth)
			if err != nil {
				return Result{}, err
			}
			res.Answers = append(chain, res.Answers...)
			return res, nil
		}

		// No direct answer: look for a referral to more authoritative
		// servers. A delegation is only trusted if it is
		//
		//   - in-bailiwick for qname (for qname itself or one of its
		//     ancestor zones), so a server cannot redirect resolution of an
		//     unrelated zone by stuffing extra NS records into its answer,
		//   - and strictly below the zone this server is authoritative for,
		//     because that is the only direction a delegation can go. That
		//     invariant is what actually terminates the walk: without it a
		//     server can keep pointing at the same zone (or back at the
		//     root) and only maxReferrals stops it, 30 round trips later.
		var newZone string
		nsNames := make(map[string]bool)
		for _, rr := range resp.Authorities {
			if rr.Type != dnsmsg.TypeNS || rr.Class != dnsmsg.ClassIN {
				continue
			}
			if !isSubdomainOrEqual(qname, rr.Name) || !isProperSubdomain(rr.Name, zone) {
				continue
			}
			// One referral delegates one zone; NS records for anything else
			// alongside it are not part of it.
			if newZone == "" {
				newZone = rr.Name
			} else if !equalName(rr.Name, newZone) {
				continue
			}
			nsNames[strings.ToLower(rr.NS)] = true
		}
		if len(nsNames) == 0 {
			// NODATA (RFC 2308 2.2): NOERROR with neither an answer nor a
			// delegation means the name exists but holds no record of this
			// type. That is an answer, not a failure - reporting it as one
			// turns the everyday "AAAA of an IPv4-only host" case into
			// SERVFAIL. The SOA (absent in a "type 3" NODATA response) is
			// passed along for the caller's negative caching.
			return Result{Authority: soaAuthority(resp.Authorities)}, nil
		}

		// Glue is a hint, not an answer: the addresses ride along in the
		// additional section purely to save a round trip, and nothing in the
		// protocol vouches for them. Only take glue for a name inside the
		// zone this server is authoritative for - that is the only part of
		// the tree it speaks for.
		//
		// Note this is the responding server's zone, not the zone being
		// delegated. Requiring glue to sit under the delegated zone instead
		// would deadlock the resolver: the root's glue for com is
		// l.gtld-servers.net, which is not under com, and resolving that
		// name needs com in the first place.
		var newServers []net.IP
		for _, rr := range resp.Additionals {
			if !nsNames[strings.ToLower(rr.Name)] || rr.Class != dnsmsg.ClassIN {
				continue
			}
			if !isSubdomainOrEqual(rr.Name, zone) {
				continue
			}
			switch {
			case rr.Type == dnsmsg.TypeA && rr.A != nil && r.allowsUpstream(rr.A):
				newServers = append(newServers, rr.A)
			case rr.Type == dnsmsg.TypeAAAA && rr.AAAA != nil && r.allowsUpstream(rr.AAAA):
				newServers = append(newServers, rr.AAAA)
			}
		}

		if len(newServers) == 0 {
			if glueDepth >= maxGlueLookups {
				return Result{}, fmt.Errorf("referral for %s has no glue and glue lookup depth exceeded", qname)
			}
			for ns := range nsNames {
				res, err := r.resolve(ns, dnsmsg.TypeA, 0, glueDepth+1)
				if err != nil {
					continue
				}
				for _, rr := range res.Answers {
					if rr.Type == dnsmsg.TypeA && rr.A != nil && r.allowsUpstream(rr.A) {
						newServers = append(newServers, rr.A)
					}
				}
				if len(newServers) > 0 {
					break
				}
			}
		}
		if len(newServers) == 0 {
			return Result{}, fmt.Errorf("could not resolve any name server address for delegation of %s", qname)
		}

		servers = newServers
		zone = newZone
	}
}

// allowsUpstream reports whether a name server address is one we are
// willing to send a query to.
//
// Nothing stops an authoritative server from handing back a private or
// loopback address as the place to ask next, which would turn the resolver
// into a probe of the network it runs on: response timing alone tells an
// attacker which internal addresses have something listening. Only DNS
// queries can be sent this way, but that is enough to map a network.
func (r *Resolver) allowsUpstream(ip net.IP) bool {
	if r.allowPrivate {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // treat IPv4-mapped IPv6 as the IPv4 address it stands for
	}
	switch {
	case ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return false
	case len(ip) == net.IPv4len && ip[0] == 100 && ip[1]&0xC0 == 64:
		return false // 100.64.0.0/10, carrier-grade NAT (RFC 6598)
	}
	return true
}

// queryServers tries each server in turn until one answers.
func (r *Resolver) queryServers(servers []net.IP, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, net.IP, error) {
	var lastErr error
	for _, s := range servers {
		// Checked again here, not only where addresses are taken from a
		// response, so that no path reaches a dial without passing it.
		if !r.allowsUpstream(s) {
			lastErr = fmt.Errorf("refusing to query name server at %s", s)
			continue
		}
		msg, err := r.query(s, qname, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		return msg, s, nil
	}
	return nil, nil, fmt.Errorf("all %d server(s) failed, last error: %w", len(servers), lastErr)
}

// query asks one server, preferring EDNS0 so that larger responses arrive
// in a single UDP datagram instead of forcing a TCP retry. Servers too old
// or too strict to accept an OPT record are retried the plain RFC 1035 way.
func (r *Resolver) query(server net.IP, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, error) {
	msg, err := r.queryOnce(server, qname, qtype, withEDNS0)
	if err == nil && ednsRefused(msg) {
		return r.queryOnce(server, qname, qtype, withoutEDNS0)
	}
	return msg, err
}

// ednsMode names queryOnce's last argument at the call site, where a bare
// true/false says nothing about what it selects.
type ednsMode bool

const (
	withEDNS0    ednsMode = true
	withoutEDNS0 ednsMode = false
)

func (r *Resolver) queryOnce(server net.IP, qname string, qtype dnsmsg.RRType, edns ednsMode) (*dnsmsg.Message, error) {
	id, err := randomQueryID()
	if err != nil {
		return nil, fmt.Errorf("generate query ID: %w", err)
	}
	var packet []byte
	if edns == withEDNS0 {
		packet, err = dnsmsg.PackQueryEDNS0(id, qname, qtype, dnsmsg.DefaultUDPSize, dnsmsg.NoDNSSEC)
	} else {
		packet, err = dnsmsg.PackQuery(id, qname, qtype)
	}
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(server.String(), r.upstreamPort())
	msg, err := queryUDP(addr, packet, id, qname, qtype)
	if err != nil {
		return nil, err
	}
	if msg.Header.TC {
		msg, err = queryTCP(addr, packet, id, qname, qtype)
		if err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// ednsRefused reports whether a response looks like the server rejected our
// query specifically because it carried an OPT record, rather than because
// the name genuinely failed to resolve.
func ednsRefused(msg *dnsmsg.Message) bool {
	switch msg.ExtendedRCode() {
	case uint16(dnsmsg.RCodeFormatError), uint16(dnsmsg.RCodeNotImplemented), dnsmsg.RCodeBadVers:
		return true
	}
	return false
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

func queryUDP(addr string, packet []byte, id uint16, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, error) {
	conn, err := net.DialTimeout("udp", addr, queryTimeout)
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

func queryTCP(addr string, packet []byte, id uint16, qname string, qtype dnsmsg.RRType) (*dnsmsg.Message, error) {
	conn, err := net.DialTimeout("tcp", addr, queryTimeout)
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
	// We only ever ask in class IN, so an answer in any other class is not
	// a reply to what we sent, whatever its name and type say.
	if msg.Questions[0].Class != dnsmsg.ClassIN {
		return nil, fmt.Errorf("response question for %s is in class %d, want IN", qname, msg.Questions[0].Class)
	}
	return msg, nil
}

// equalName compares domain names ignoring case and a trailing root dot.
func equalName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// isProperSubdomain reports whether name is strictly below zone. It is the
// invariant a referral has to satisfy: delegation only ever moves down the
// tree, so a server answering for zone may only send us to a zone under it.
func isProperSubdomain(name, zone string) bool {
	return !equalName(name, zone) && isSubdomainOrEqual(name, zone)
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
