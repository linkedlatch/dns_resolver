package dnsserver

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"dns_resolver/dnsmsg"
)

const (
	// maxUDPResponseSize is the classic (pre-EDNS0) UDP response limit;
	// larger responses must be truncated (TC=1) so the client retries
	// over TCP. EDNS0 buffer-size negotiation is a later addition.
	maxUDPResponseSize = 512
	maxUDPPacketSize   = 4096
	tcpConnTimeout     = 5 * time.Second
)

// Server listens for DNS queries on both UDP and TCP at Addr and dispatches
// each one to Handler.
type Server struct {
	Addr    string
	Handler Handler
}

// ListenAndServe listens on Addr for both UDP and TCP and blocks, serving
// requests until either listener returns an error.
func (s *Server) ListenAndServe() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer udpConn.Close()

	tcpLn, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}
	defer tcpLn.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- s.serveUDP(udpConn) }()
	go func() { errCh <- s.serveTCP(tcpLn) }()
	return <-errCh
}

func (s *Server) serveUDP(conn *net.UDPConn) error {
	for {
		buf := make([]byte, maxUDPPacketSize)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		go s.handleUDPQuery(conn, addr, buf[:n])
	}
}

func (s *Server) handleUDPQuery(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	req, err := dnsmsg.Unpack(data)
	if err != nil {
		return // drop malformed queries silently, as most DNS servers do
	}

	w := &udpResponseWriter{conn: conn, addr: addr, maxSize: maxUDPResponseSize}
	// A client that sent an OPT record can accept responses larger than the
	// classic 512-byte limit, which avoids truncating and making it retry
	// over TCP. Cap what we honor at our own buffer size so a client can't
	// make us build an oversized datagram by claiming a huge one.
	if opt := req.OPT(); opt != nil {
		w.clientUsedEDNS0 = true
		if size := int(opt.UDPSize()); size > w.maxSize {
			w.maxSize = min(size, maxUDPPacketSize)
		}
	}
	s.Handler.ServeDNS(w, req)
}

type udpResponseWriter struct {
	conn            *net.UDPConn
	addr            *net.UDPAddr
	maxSize         int
	clientUsedEDNS0 bool
}

func (w *udpResponseWriter) WriteMsg(msg *dnsmsg.Message) error {
	out := *msg
	if w.clientUsedEDNS0 {
		out.Additionals = withOPT(msg.Additionals, w.maxSize)
	}

	packet, err := dnsmsg.Pack(&out)
	if err != nil {
		return err
	}
	if len(packet) > w.maxSize {
		// Drop the records but keep the question and OPT, so the client
		// sees TC and knows to retry over TCP.
		out.Header.TC = true
		out.Answers = nil
		out.Authorities = nil
		packet, err = dnsmsg.Pack(&out)
		if err != nil {
			return err
		}
	}
	_, err = w.conn.WriteToUDP(packet, w.addr)
	return err
}

// withOPT returns additionals with our own OPT record in place of any the
// handler produced, as RFC 6891 requires an EDNS0-aware responder to answer
// an EDNS0 query with an OPT record of its own.
func withOPT(additionals []dnsmsg.RR, udpSize int) []dnsmsg.RR {
	out := make([]dnsmsg.RR, 0, len(additionals)+1)
	for _, rr := range additionals {
		if rr.Type != dnsmsg.TypeOPT {
			out = append(out, rr)
		}
	}
	return append(out, dnsmsg.NewOPT(uint16(udpSize), dnsmsg.NoDNSSEC))
}

func (s *Server) serveTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleTCPConn(conn)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(tcpConnTimeout))

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return
	}

	req, err := dnsmsg.Unpack(data)
	if err != nil {
		return
	}
	s.Handler.ServeDNS(&tcpResponseWriter{conn: conn, clientUsedEDNS0: req.OPT() != nil}, req)
}

type tcpResponseWriter struct {
	conn            net.Conn
	clientUsedEDNS0 bool
}

func (w *tcpResponseWriter) WriteMsg(msg *dnsmsg.Message) error {
	out := *msg
	// TCP responses are length-prefixed and need no truncation, but an
	// EDNS0 query still has to be answered with an OPT record.
	if w.clientUsedEDNS0 {
		out.Additionals = withOPT(msg.Additionals, maxUDPPacketSize)
	}
	packet, err := dnsmsg.Pack(&out)
	if err != nil {
		return err
	}
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(packet)))
	_, err = w.conn.Write(append(lenPrefix, packet...))
	return err
}
