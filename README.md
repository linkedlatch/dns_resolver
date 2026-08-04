# dns_resolver

A recursive DNS resolver and server, written from the wire format up in Go
with no third-party dependencies.

It answers a query the way `dig +trace` does: starting at the root servers
and following NS referrals down to the servers authoritative for the name,
rather than forwarding the question to someone else's resolver.

> **Do not put this on the public internet.** It is a project written to
> understand DNS, not a hardened production resolver. It binds to loopback
> and refuses every other client by default; that default is doing real
> work, and changing it makes this machine an amplifier for attacks on
> other people. See [Limitations](#limitations) for what is missing.

## Building and running

```
go build ./cmd/server     # the resolver as a DNS server
go build ./cmd/resolve    # one-shot lookups from the command line
```

```
$ ./resolve www.wikipedia.org
103.102.166.224

$ ./server -addr 127.0.0.1:5353
$ dig @127.0.0.1 -p 5353 example.com A
```

With a configuration file:

```
$ ./server -config resolver.json
```

```json
{
  "listen": "127.0.0.1:5353",
  "allow": ["127.0.0.0/8", "10.0.0.0/8"],
  "dnssec": true,
  "qname_minimization": true,
  "middleware": ["acl", "ratelimit", "cache", "singleflight"],
  "log_format": "json"
}
```

Every field has a default, so a file only has to mention what it changes.
The full set is documented on `config.Config` in
[config/config.go](config/config.go).

## Architecture

```
  client
    |
    v
 dnsserver ──> acl ──> ratelimit ──> cache ──> singleflight ──> resolverhandler
  UDP/TCP/TLS   |          |           |            |                  |
  listeners     |          |           |            |                  v
                |          |           |            |               resolver
      allowed   |   per-source rate  answers    collapses         iterative walk
      prefixes  |      limiting      within     identical         from the root
                |                     TTL       in-flight              |
                                                queries                v
                                                                    dnssec
                                                             signature validation
```

The server does one thing: read a message, hand it to a `Handler`, write the
reply. Everything else is a `Handler` that wraps another one, which is why
access control, rate limiting, caching and de-duplication could each be
added without touching the layers around them. The chain is assembled from
the `middleware` list in the configuration.

The resolver keeps two caches of its own, separate from the response cache:
the servers authoritative for each zone, so a second name in a zone does not
walk from the root again, and the validated DNSKEY set for each signed zone.

| Package | What it does |
| --- | --- |
| [dnsmsg](dnsmsg/) | Wire format: encoding, decoding, EDNS0, DNSSEC records |
| [dnsserver](dnsserver/) | UDP, TCP and TLS listeners; the `Handler` interface |
| [resolver](resolver/) | The iterative walk, caches, DNSSEC chain of trust |
| [dnssec](dnssec/) | Signature and digest verification |
| [middleware](middleware/) | `acl`, `ratelimit`, `cache`, `singleflight` |
| [resolverhandler](resolverhandler/) | Resolution outcomes to DNS response codes |
| [config](config/) | Settings and the configuration file |

## What it supports

- Iterative resolution from the root, with CNAME chains, NODATA, NXDOMAIN
- Any query type: the ones it parses (A, AAAA, NS, CNAME, SOA, MX, PTR,
  DNSSEC records) and the rest passed through as raw RDATA
- EDNS0, with a plain retry for servers that reject it, and TCP fallback on
  truncation
- DNSSEC validation from the root trust anchor, with the AD bit on answers
  proven authentic and SERVFAIL for ones that fail
- NSEC denial of existence: an unsigned delegation, an NXDOMAIN, an empty
  answer and a wildcard expansion each have to be proven, not just asserted
- QNAME minimization (RFC 9156), optional 0x20 encoding
- Root priming (RFC 8109), IPv4 and IPv6 root servers
- Caching of positive, NODATA, NXDOMAIN and SERVFAIL answers, with the
  RFC 8020 NXDOMAIN cut; a delegation cache; single-flight de-duplication
- Retries and RTT-based server selection
- UDP, TCP with connection reuse, and DNS-over-TLS
- Access control, per-client rate limiting, in-flight limits, graceful
  shutdown

## Limitations

- **NSEC3 denial of existence is not checked.** Its records are parsed but
  their hashed names are not, so a zone using NSEC3 - which is most of the
  popular TLDs - is still taken at its word when it says a delegation is
  unsigned. An attacker able to strip the DS records from such a referral
  can downgrade a signed zone to unsigned. The same attack against an
  NSEC-signed zone is now rejected.
- **No RFC 5011 key rollover.** The root trust anchor is compiled in, so a
  root key rollover means shipping a new binary.
- **No DNS-over-HTTPS**, no zone data of its own, no forwarding mode.
- The cache is in memory only and is lost on restart.

## Tests

```
go test ./... -race
```

The resolver's tests run against a fake authoritative server on loopback
rather than the internet, so the delegation walk, CNAME handling, bailiwick
rules, truncation and EDNS0 fallbacks are all exercised without leaving the
machine.
