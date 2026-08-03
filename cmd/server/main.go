package main

import (
	"errors"
	"flag"
	"log"

	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
	"dns_resolver/resolver"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5353", "address to listen on for DNS queries (UDP and TCP)")
	flag.Parse()

	srv := &dnsserver.Server{
		Addr:    *addr,
		Handler: &resolverHandler{r: resolver.New()},
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

	answers, err := h.r.ResolveRR(q.Name, q.Type)
	switch {
	case err == nil:
		resp.Answers = answers
	case errors.Is(err, resolver.ErrNXDOMAIN):
		resp.Header.RCode = dnsmsg.RCodeNameError
	default:
		log.Printf("resolve %s %s: %v", q.Name, q.Type, err)
		resp.Header.RCode = dnsmsg.RCodeServerFailure
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("write response for %s %s: %v", q.Name, q.Type, err)
	}
}
