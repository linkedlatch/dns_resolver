package main

import (
	"fmt"
	"os"
	"strings"

	"dns_resolver/dnsmsg"
	"dns_resolver/resolver"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <domain> [A|AAAA]\n", os.Args[0])
		os.Exit(2)
	}

	name := os.Args[1]
	qtype := dnsmsg.TypeA
	if len(os.Args) == 3 {
		switch strings.ToUpper(os.Args[2]) {
		case "A":
			qtype = dnsmsg.TypeA
		case "AAAA":
			qtype = dnsmsg.TypeAAAA
		default:
			fmt.Fprintf(os.Stderr, "unsupported query type %q (only A and AAAA are supported)\n", os.Args[2])
			os.Exit(2)
		}
	}

	ips, err := resolver.New().Resolve(name, qtype)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve %s %s: %v\n", name, qtype, err)
		os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Println(ip)
	}
}
