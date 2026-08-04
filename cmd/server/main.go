package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dns_resolver/config"
	"dns_resolver/dnsmsg"
	"dns_resolver/dnsserver"
	"dns_resolver/middleware/acl"
	"dns_resolver/middleware/cache"
	"dns_resolver/middleware/ratelimit"
	"dns_resolver/middleware/singleflight"
	"dns_resolver/resolver"
	"dns_resolver/resolverhandler"
)

func main() {
	configPath := flag.String("config", "", "path to a JSON configuration file")
	listen := flag.String("addr", "", "address to listen on, overriding the configuration")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration: %v\n", err)
		os.Exit(1)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "configuration: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg)
	handler, err := buildHandler(cfg, logger)
	if err != nil {
		logger.Error("build handler", "error", err)
		os.Exit(1)
	}

	srv := &dnsserver.Server{
		Addr:         cfg.Listen,
		Handler:      handler,
		QueryTimeout: time.Duration(cfg.QueryTimeout),
		MaxInFlight:  cfg.MaxInFlight,
	}
	if cfg.TLSListen != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			logger.Error("load TLS certificate", "error", err)
			os.Exit(1)
		}
		srv.TLSAddr = cfg.TLSListen
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// A signal cancels the context, which stops the listeners and lets the
	// queries already in progress finish before the process exits.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("listening",
		"addr", cfg.Listen,
		"tls_addr", cfg.TLSListen,
		"allow", cfg.Allow,
		"dnssec", cfg.DNSSEC,
		"trust_anchor", cfg.TrustAnchor,
		"middleware", cfg.Middleware,
	)
	if err := srv.ListenAndServe(ctx); err != nil {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
	logger.Info("shut down")
}

// buildHandler assembles the middleware chain named in the configuration
// around the resolver, so the behaviour of the server can be changed
// without rebuilding it.
func buildHandler(cfg config.Config, logger *slog.Logger) (dnsserver.Handler, error) {
	allowed, err := cfg.AllowedPrefixes()
	if err != nil {
		return nil, err
	}

	var anchors []dnsmsg.DS
	if cfg.TrustAnchor != "" {
		// Failing to start beats starting with the wrong anchors: a resolver
		// that quietly fell back to the built-in copy would validate against
		// a key the operator had deliberately replaced.
		if anchors, err = resolver.LoadTrustAnchors(cfg.TrustAnchor); err != nil {
			return nil, fmt.Errorf("trust anchor: %w", err)
		}
	}

	r := resolver.NewWithOptions(resolver.Options{
		UpstreamTimeout:          time.Duration(cfg.UpstreamTimeout),
		DisableDNSSEC:            !cfg.DNSSEC,
		DisableQNAMEMinimization: !cfg.QNAMEMinimization,
		Use0x20:                  cfg.Use0x20,
		TrustAnchors:             anchors,
	})
	handler := resolverhandler.New(r, logger)

	// The list reads outermost first, which is the order queries meet it,
	// so it is applied in reverse.
	for i := len(cfg.Middleware) - 1; i >= 0; i-- {
		switch name := cfg.Middleware[i]; name {
		case "acl":
			handler = acl.Wrap(handler, allowed)
		case "ratelimit":
			handler = ratelimit.Wrap(handler, cfg.RateLimit, cfg.Burst)
		case "cache":
			handler = cache.Wrap(handler, cache.Config{
				MaxEntries: cfg.CacheEntries,
				MinTTL:     time.Duration(cfg.CacheMinTTL),
				MaxTTL:     time.Duration(cfg.CacheMaxTTL),
			})
		case "singleflight":
			handler = singleflight.Wrap(handler)
		default:
			return nil, fmt.Errorf("unknown middleware %q", name)
		}
	}
	return handler, nil
}

func newLogger(cfg config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
