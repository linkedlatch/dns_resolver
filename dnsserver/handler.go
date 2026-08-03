// Package dnsserver provides a minimal UDP/TCP DNS server that dispatches
// incoming queries to a Handler, mirroring the net/http server/Handler
// split so that features (caching, rate limiting, ...) can later be added
// as Handlers that wrap another Handler, without touching this package.
package dnsserver

import (
	"context"
	"net"

	"dns_resolver/dnsmsg"
)

// ResponseWriter lets a Handler send the completed response for the query
// it was given, and tells it where the query came from - which an access
// control or rate limiting Handler needs to make its decision.
type ResponseWriter interface {
	WriteMsg(msg *dnsmsg.Message) error
	RemoteAddr() net.Addr
}

// Handler answers a single DNS query.
//
// ctx carries the deadline for the whole query and is cancelled when the
// server shuts down, so a Handler doing work of its own (resolution,
// upstream requests) must pass it along and stop when it is done.
type Handler interface {
	ServeDNS(ctx context.Context, w ResponseWriter, req *dnsmsg.Message)
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(ctx context.Context, w ResponseWriter, req *dnsmsg.Message)

func (f HandlerFunc) ServeDNS(ctx context.Context, w ResponseWriter, req *dnsmsg.Message) {
	f(ctx, w, req)
}
