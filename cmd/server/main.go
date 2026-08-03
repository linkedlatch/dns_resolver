package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os/signal"
	"strings"
	"syscall"

	"dns_resolver/dnsserver"
	"dns_resolver/middleware/acl"
	"dns_resolver/middleware/cache"
	"dns_resolver/middleware/ratelimit"
	"dns_resolver/resolver"
	"dns_resolver/resolverhandler"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5353", "address to listen on for DNS queries (UDP and TCP)")
	allow := flag.String("allow", "", "comma-separated CIDRs allowed to query this server (default: loopback only)")
	rate := flag.Float64("rate", 0, "queries per second allowed per client address (0: built-in default)")
	maxInFlight := flag.Int("max-in-flight", 0, "queries that may be resolved at once (0: built-in default)")
	flag.Parse()

	allowed, err := parsePrefixes(*allow)
	if err != nil {
		log.Fatalf("-allow: %v", err)
	}

	// Innermost first: resolution, then cache, then the checks that should
	// run before any work is done on a query.
	handler := resolverhandler.New(resolver.New())
	handler = cache.Wrap(handler, 0)
	handler = ratelimit.Wrap(handler, *rate, 0)
	handler = acl.Wrap(handler, allowed)

	srv := &dnsserver.Server{
		Addr:        *addr,
		Handler:     handler,
		MaxInFlight: *maxInFlight,
	}

	// A signal cancels the context, which stops the listeners and lets the
	// queries already in progress finish before the process exits.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("listening on %s (udp+tcp), answering %s", *addr, allowed)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatal(err)
	}
	log.Print("shut down")
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	if strings.TrimSpace(s) == "" {
		return acl.LoopbackOnly(), nil
	}
	var out []netip.Prefix
	for _, field := range strings.Split(s, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(field))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
