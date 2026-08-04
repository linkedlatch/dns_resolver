// Package config holds the settings that decide how the server behaves,
// and reads them from a file.
//
// The values here are the ones that genuinely differ between deployments -
// timeouts that depend on link quality, limits that depend on load, an
// allow list that depends on the network - rather than knobs invented for
// their own sake. Until now they were compile-time constants, so changing
// any of them meant rebuilding.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Config is a whole server configuration. Every field has a working default,
// so an empty file, or no file at all, still starts a usable server.
type Config struct {
	// Listen is the address for both the UDP and TCP listeners.
	Listen string `json:"listen"`

	// Allow lists the client prefixes that may query this server. Empty
	// means loopback only: a resolver that answers the whole internet is an
	// amplifier for attacks on other people.
	Allow []string `json:"allow"`

	// RateLimit caps queries per second from one client address, with Burst
	// as the allowance a client may run ahead by.
	RateLimit float64 `json:"rate_limit"`
	Burst     float64 `json:"burst"`

	// MaxInFlight bounds how many queries may be resolved at once.
	MaxInFlight int `json:"max_in_flight"`

	// QueryTimeout bounds one client query end to end, and UpstreamTimeout
	// bounds a single exchange with one name server.
	QueryTimeout    Duration `json:"query_timeout"`
	UpstreamTimeout Duration `json:"upstream_timeout"`

	// CacheEntries is the size of the response cache. CacheMinTTL and
	// CacheMaxTTL bound how long an entry lives whatever TTL it carried.
	CacheEntries int      `json:"cache_entries"`
	CacheMinTTL  Duration `json:"cache_min_ttl"`
	CacheMaxTTL  Duration `json:"cache_max_ttl"`

	// TLSListen, with TLSCert and TLSKey, adds a DNS-over-TLS listener
	// (RFC 7858), conventionally on port 853.
	TLSListen string `json:"tls_listen"`
	TLSCert   string `json:"tls_cert"`
	TLSKey    string `json:"tls_key"`

	// QNAMEMinimization sends each server only as much of the name as it
	// needs to answer, rather than the whole thing (RFC 9156).
	QNAMEMinimization bool `json:"qname_minimization"`

	// Use0x20 randomizes the case of queried names as extra entropy against
	// forged replies. Off by default: a server that does not echo the case
	// back exactly breaks resolution outright.
	Use0x20 bool `json:"use_0x20"`

	// DNSSEC turns signature validation on. With it off, answers are served
	// unchecked and never marked authentic.
	DNSSEC bool `json:"dnssec"`

	// Middleware names the wrappers to build around the resolver, outermost
	// first, so the chain can be changed without recompiling.
	Middleware []string `json:"middleware"`

	// LogLevel is "debug", "info", "warn" or "error".
	LogLevel string `json:"log_level"`
	// LogFormat is "text" or "json".
	LogFormat string `json:"log_format"`
}

// Default is the configuration used when nothing says otherwise: bound to
// loopback, validating, with limits sized for a personal resolver.
func Default() Config {
	return Config{
		Listen:            "127.0.0.1:5353",
		Allow:             []string{"127.0.0.0/8", "::1/128"},
		RateLimit:         50,
		Burst:             100,
		MaxInFlight:       512,
		QueryTimeout:      Duration(10 * time.Second),
		UpstreamTimeout:   Duration(3 * time.Second),
		CacheEntries:      10000,
		CacheMinTTL:       Duration(5 * time.Second),
		CacheMaxTTL:       Duration(24 * time.Hour),
		DNSSEC:            true,
		QNAMEMinimization: true,
		Middleware:        []string{"acl", "ratelimit", "cache", "singleflight"},
		LogLevel:          "info",
		LogFormat:         "text",
	}
}

// Load reads a configuration file, filling anything it does not set from
// the defaults. An empty path returns the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	// Decoding onto the defaults means a file only has to mention what it
	// changes, and a field added later does not break existing files.
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate reports settings that would produce a server that cannot work,
// or that would quietly do something other than what was asked.
func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is empty")
	}
	if c.TLSListen != "" && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("tls_listen is set but tls_cert and tls_key are not")
	}
	if _, err := c.AllowedPrefixes(); err != nil {
		return err
	}
	if c.CacheMinTTL > c.CacheMaxTTL {
		return fmt.Errorf("cache_min_ttl (%s) is above cache_max_ttl (%s)",
			time.Duration(c.CacheMinTTL), time.Duration(c.CacheMaxTTL))
	}
	if c.UpstreamTimeout > c.QueryTimeout {
		return fmt.Errorf("upstream_timeout (%s) is above query_timeout (%s), so a single server could use the whole budget",
			time.Duration(c.UpstreamTimeout), time.Duration(c.QueryTimeout))
	}
	for _, name := range c.Middleware {
		switch name {
		case "acl", "ratelimit", "cache", "singleflight":
		default:
			return fmt.Errorf("unknown middleware %q", name)
		}
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("unknown log_format %q", c.LogFormat)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unknown log_level %q", c.LogLevel)
	}
	return nil
}

// AllowedPrefixes parses the allow list.
func (c Config) AllowedPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Allow))
	for _, s := range c.Allow {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("allow %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Duration is a time.Duration that reads from JSON as a string like "3s",
// because a bare number in a config file gives no clue whether it means
// seconds or nanoseconds.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"3s\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}
