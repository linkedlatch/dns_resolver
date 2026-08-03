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
	s.Handler.ServeDNS(&udpResponseWriter{conn: conn, addr: addr}, req)
}

type udpResponseWriter struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (w *udpResponseWriter) WriteMsg(msg *dnsmsg.Message) error {
	packet, err := dnsmsg.Pack(msg)
	if err != nil {
		return err
	}
	if len(packet) > maxUDPResponseSize {
		truncated := *msg
		truncated.Header.TC = true
		truncated.Answers = nil
		truncated.Authorities = nil
		truncated.Additionals = nil
		packet, err = dnsmsg.Pack(&truncated)
		if err != nil {
			return err
		}
	}
	_, err = w.conn.WriteToUDP(packet, w.addr)
	return err
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
	s.Handler.ServeDNS(&tcpResponseWriter{conn: conn}, req)
}

type tcpResponseWriter struct {
	conn net.Conn
}

func (w *tcpResponseWriter) WriteMsg(msg *dnsmsg.Message) error {
	packet, err := dnsmsg.Pack(msg)
	if err != nil {
		return err
	}
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(packet)))
	_, err = w.conn.Write(append(lenPrefix, packet...))
	return err
}
