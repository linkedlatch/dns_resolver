// Package acl is a dnsserver.Handler middleware that answers only clients
// whose address is on a list of allowed prefixes.
//
// A recursive resolver reachable by anyone is not merely a resource being
// used for free: it answers small queries with large responses, which makes
// it a usable amplifier for attacks on third parties with a spoofed source
// address. Access control is what keeps a resolver from becoming one, which
// is why it belongs here rather than in a deployment note nobody reads.
package acl

import (
	"context"
	"net"
	"net/netip"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
)

type handler struct {
	next    dnsserver.Handler
	allowed []netip.Prefix
}

// Wrap returns a Handler that passes queries from allowed to next and
// refuses everything else. An empty list refuses everything.
func Wrap(next dnsserver.Handler, allowed []netip.Prefix) dnsserver.Handler {
	return &handler{next: next, allowed: allowed}
}

// LoopbackOnly is the default policy: answer this machine and nothing else.
func LoopbackOnly() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
}

func (h *handler) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, req *dnsmsg.Message) {
	if h.permits(w.RemoteAddr()) {
		h.next.ServeDNS(ctx, w, req)
		return
	}

	// REFUSED rather than silence: a refused client learns immediately that
	// it has the wrong server, and the reply is no larger than the query,
	// so it is of no use for amplification.
	w.WriteMsg(&dnsmsg.Message{
		Header: dnsmsg.Header{
			ID:     req.Header.ID,
			QR:     true,
			Opcode: req.Header.Opcode,
			RD:     req.Header.RD,
			RCode:  dnsmsg.RCodeRefused,
		},
		Questions: req.Questions,
	})
}

func (h *handler) permits(addr net.Addr) bool {
	ip, ok := addrIP(addr)
	if !ok {
		return false
	}
	for _, p := range h.allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// addrIP extracts the client address, unwrapping the IPv4-in-IPv6 form a
// dual-stack listener reports so that a 127.0.0.1 client is not compared
// against the allow list as ::ffff:127.0.0.1.
func addrIP(addr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}
