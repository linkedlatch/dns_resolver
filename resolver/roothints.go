package resolver

import "net"

// RootServers are the well-known IPv4 addresses of the 13 root DNS servers
// (see https://www.iana.org/domains/root/servers).
var RootServers = []net.IP{
	net.ParseIP("198.41.0.4"),     // a.root-servers.net
	net.ParseIP("199.9.14.201"),   // b.root-servers.net
	net.ParseIP("192.33.4.12"),    // c.root-servers.net
	net.ParseIP("199.7.91.13"),    // d.root-servers.net
	net.ParseIP("192.203.230.10"), // e.root-servers.net
	net.ParseIP("192.5.5.241"),    // f.root-servers.net
	net.ParseIP("192.112.36.4"),   // g.root-servers.net
	net.ParseIP("198.97.190.53"),  // h.root-servers.net
	net.ParseIP("192.36.148.17"),  // i.root-servers.net
	net.ParseIP("192.58.128.30"),  // j.root-servers.net
	net.ParseIP("193.0.14.129"),   // k.root-servers.net
	net.ParseIP("199.7.83.42"),    // l.root-servers.net
	net.ParseIP("202.12.27.33"),   // m.root-servers.net
}
