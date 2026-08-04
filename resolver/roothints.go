package resolver

import "net"

// rootHints are the addresses of the root servers as of the last time this
// file was updated (https://www.iana.org/domains/root/servers).
//
// They are hints, not the answer: their only job is to get one query
// through to any root server, which then tells us the live set (see
// priming, RFC 8109). That is why a few of them going stale is survivable -
// the list is tried in turn - and why the names matter less than the
// addresses.
//
// Both address families are listed. Without the IPv6 addresses a resolver
// on an IPv6-only network cannot bootstrap at all, having no way to reach
// the first server it needs to ask.
var rootHints = []rootServer{
	{"a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30"},
	{"b.root-servers.net", "170.247.170.2", "2801:1b8:10::b"},
	{"c.root-servers.net", "192.33.4.12", "2001:500:2::c"},
	{"d.root-servers.net", "199.7.91.13", "2001:500:2d::d"},
	{"e.root-servers.net", "192.203.230.10", "2001:500:a8::e"},
	{"f.root-servers.net", "192.5.5.241", "2001:500:2f::f"},
	{"g.root-servers.net", "192.112.36.4", "2001:500:12::d0d"},
	{"h.root-servers.net", "198.97.190.53", "2001:500:1::53"},
	{"i.root-servers.net", "192.36.148.17", "2001:7fe::53"},
	{"j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30"},
	{"k.root-servers.net", "193.0.14.129", "2001:7fd::1"},
	{"l.root-servers.net", "199.7.83.42", "2001:500:9f::42"},
	{"m.root-servers.net", "202.12.27.33", "2001:dc3::35"},
}

type rootServer struct {
	name string
	v4   string
	v6   string
}

// RootServers are the addresses to start from before anything better is
// known.
var RootServers = rootHintAddresses()

func rootHintAddresses() []net.IP {
	out := make([]net.IP, 0, 2*len(rootHints))
	for _, s := range rootHints {
		if ip := net.ParseIP(s.v4); ip != nil {
			out = append(out, ip)
		}
		if ip := net.ParseIP(s.v6); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
