// Package dnsserver provides a minimal UDP/TCP DNS server that dispatches
// incoming queries to a Handler, mirroring the net/http server/Handler
// split so that features (caching, rate limiting, ...) can later be added
// as Handlers that wrap another Handler, without touching this package.
package dnsserver

import "dns_resolver/dnsmsg"

// ResponseWriter lets a Handler send the completed response for the query
// it was given.
type ResponseWriter interface {
	WriteMsg(msg *dnsmsg.Message) error
}

// Handler answers a single DNS query.
type Handler interface {
	ServeDNS(w ResponseWriter, req *dnsmsg.Message)
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(w ResponseWriter, req *dnsmsg.Message)

func (f HandlerFunc) ServeDNS(w ResponseWriter, req *dnsmsg.Message) {
	f(w, req)
}
