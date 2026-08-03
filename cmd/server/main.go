package main

import (
	"errors"
	"flag"
	"log"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
	"dns_resolver/middleware/cache"
	"dns_resolver/resolver"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5353", "address to listen on for DNS queries (UDP and TCP)")
	flag.Parse()

	base := &resolverHandler{r: resolver.New()}
	srv := &dnsserver.Server{
		Addr:    *addr,
		Handler: cache.Wrap(base, 0),
	}
	log.Printf("listening on %s (udp+tcp)", *addr)
	log.Fatal(srv.ListenAndServe())
}

// resolverHandler bridges dnsserver.Handler to resolver.Resolver: it's the
// innermost handler in what will become a middleware chain (cache, rate
// limiting, etc. wrapping this) as the server grows more features.
type resolverHandler struct {
	r *resolver.Resolver
}

func (h *resolverHandler) ServeDNS(w dnsserver.ResponseWriter, req *dnsmsg.Message) {
	resp := &dnsmsg.Message{
		Header: dnsmsg.Header{
			ID: req.Header.ID,
			QR: true,
			RD: req.Header.RD,
			RA: true,
		},
		Questions: req.Questions,
	}

	if len(req.Questions) != 1 {
		resp.Header.RCode = dnsmsg.RCodeFormatError
		w.WriteMsg(resp)
		return
	}
	q := req.Questions[0]

	res, err := h.r.ResolveRR(q.Name, q.Type)
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
