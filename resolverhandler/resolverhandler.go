// Package resolverhandler bridges a resolver to the dnsserver.Handler
// interface: it is the innermost handler of the middleware chain, the one
// that actually answers a query, with cache, access control and the rest
// wrapping it.
//
// It lives in its own package rather than in the server command so that the
// mapping it performs - resolution outcomes to RCODEs - can be tested.
package resolverhandler

import (
	"context"
	"errors"
	"log"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
	"dns_resolver/resolver"
)

// opcodeQuery is the only opcode we implement. The others (IQUERY, STATUS,
// NOTIFY, UPDATE) are separate protocols sharing the message format.
const opcodeQuery = 0

type handler struct {
	r *resolver.Resolver
}

// New returns a Handler answering queries by resolving them with r.
func New(r *resolver.Resolver) dnsserver.Handler {
	return &handler{r: r}
}

func (h *handler) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, req *dnsmsg.Message) {
	resp := &dnsmsg.Message{
		Header: dnsmsg.Header{
			ID:     req.Header.ID,
			QR:     true,
			Opcode: req.Header.Opcode,
			RD:     req.Header.RD,
			RA:     true,
		},
		Questions: req.Questions,
	}

	// Anything that is not a standard query has to be refused explicitly.
	// Treating an UPDATE as if it were a QUERY is a dangerous default to
	// leave in place for whenever this server does learn to hold zone data.
	if req.Header.Opcode != opcodeQuery {
		resp.Header.RCode = dnsmsg.RCodeNotImplemented
		w.WriteMsg(resp)
		return
	}
	if len(req.Questions) != 1 {
		resp.Header.RCode = dnsmsg.RCodeFormatError
		w.WriteMsg(resp)
		return
	}
	q := req.Questions[0]

	res, err := h.r.ResolveRR(ctx, q.Name, q.Type)
	var nxErr *resolver.NXDOMAINError
	switch {
	case err == nil:
		// A NODATA result (name exists, no record of this type) arrives here
		// too, as an empty answer section plus the zone's SOA: NOERROR with
		// no answers is the correct reply for it, not an error.
		resp.Answers = res.Answers
		resp.Authorities = res.Authority
	case errors.As(err, &nxErr):
		resp.Header.RCode = dnsmsg.RCodeNameError
		if nxErr.SOA != nil {
			// Carrying the SOA through lets a downstream cache derive the
			// correct negative-caching TTL (RFC 2308) from the response
			// itself, and matches what a real authoritative/recursive
			// server sends a client on NXDOMAIN.
			resp.Authorities = []dnsmsg.RR{*nxErr.SOA}
		}
	default:
		log.Printf("resolve %s %s: %v", q.Name, q.Type, err)
		resp.Header.RCode = dnsmsg.RCodeServerFailure
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("write response for %s %s: %v", q.Name, q.Type, err)
	}
}
