package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"dns_resolver/dnsmsg"
)

const (
	// maxUDPResponseSize is the classic (pre-EDNS0) UDP response limit;
	// larger responses must be truncated (TC=1) so the client retries
	// over TCP. EDNS0 buffer-size negotiation is a later addition.
	maxUDPResponseSize = 512
	maxUDPPacketSize   = 4096

	// tcpIdleTimeout is how long a connection may sit between queries
	// before we close it. A client is free to send several queries over one
	// connection (RFC 7766), so the connection cannot be closed after the
	// first, but it must not be held open indefinitely either.
	tcpIdleTimeout = 10 * time.Second

	// defaultQueryTimeout bounds one query end to end. The resolver's own
	// timeout is per socket, which puts no ceiling on a resolution that
	// keeps making progress across dozens of servers.
	defaultQueryTimeout = 10 * time.Second

	// defaultMaxInFlight bounds how many queries may be in progress at
	// once. Each one can occupy a goroutine and upstream sockets for
	// seconds, so without a ceiling a flood of queries for names that have
	// to be resolved from scratch (random subdomains of a victim domain,
	// say) exhausts memory and file descriptors.
	defaultMaxInFlight = 512
)

// Server listens for DNS queries on both UDP and TCP at Addr and dispatches
// each one to Handler.
type Server struct {
	Addr    string
	Handler Handler

	// QueryTimeout bounds the time spent on one query; MaxInFlight bounds
	// how many may run at once. Zero means the built-in default.
	QueryTimeout time.Duration
	MaxInFlight  int

	sem chan struct{}
	wg  sync.WaitGroup
}

// ListenAndServe listens on Addr for both UDP and TCP and blocks until ctx
// is cancelled or a listener fails.
//
// On cancellation it stops accepting, then waits for the queries already in
// progress to finish, so a shutdown does not cut off answers that clients
// are still waiting for.
func (s *Server) ListenAndServe(ctx context.Context) error {
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

	return s.Serve(ctx, udpConn, tcpLn)
}

// Serve is ListenAndServe on listeners the caller has already opened, for
// when the address has to be bound before the server starts (a socket
// passed in by an init system, a test that needs the port up front).
func (s *Server) Serve(ctx context.Context, udpConn *net.UDPConn, tcpLn net.Listener) error {
	s.sem = make(chan struct{}, s.maxInFlight())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Closing the listeners is what unblocks the two accept loops; there is
	// no other way to interrupt a blocking Read or Accept.
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		udpConn.Close()
		tcpLn.Close()
		close(closed)
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- s.serveUDP(ctx, udpConn) }()
	go func() { errCh <- s.serveTCP(ctx, tcpLn) }()

	err := <-errCh
	cancel()
	<-closed
	s.wg.Wait()
	if ctx.Err() != nil && errors.Is(err, net.ErrClosed) {
		return nil // the listener closed because we asked it to
	}
	return err
}

func (s *Server) maxInFlight() int {
	if s.MaxInFlight > 0 {
		return s.MaxInFlight
	}
	return defaultMaxInFlight
}

func (s *Server) queryTimeout() time.Duration {
	if s.QueryTimeout > 0 {
		return s.QueryTimeout
	}
	return defaultQueryTimeout
}

// start runs fn as a query in progress, unless the server is already at its
// in-flight limit, in which case it reports false and the caller drops the
// query. Dropping is what a DNS server does when it is overloaded: the
// client's own retry is a better queue than an unbounded one here.
func (s *Server) start(fn func()) bool {
	select {
	case s.sem <- struct{}{}:
	default:
		return false
	}
	s.wg.Add(1)
	go func() {
		defer func() {
			<-s.sem
			s.wg.Done()
		}()
		fn()
	}()
	return true
}

func (s *Server) serveUDP(ctx context.Context, conn *net.UDPConn) error {
	for {
		buf := make([]byte, maxUDPPacketSize)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		data := buf[:n]
		s.start(func() { s.handleUDPQuery(ctx, conn, addr, data) })
	}
}

func (s *Server) handleUDPQuery(ctx context.Context, conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
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

	ctx, cancel := context.WithTimeout(ctx, s.queryTimeout())
	defer cancel()
	s.Handler.ServeDNS(ctx, w, req)
}

type udpResponseWriter struct {
	conn            *net.UDPConn
	addr            *net.UDPAddr
	maxSize         int
	clientUsedEDNS0 bool
}

func (w *udpResponseWriter) RemoteAddr() net.Addr { return w.addr }

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

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if !s.start(func() { s.handleTCPConn(ctx, conn) }) {
			conn.Close()
		}
	}
}

// handleTCPConn serves queries from one connection until it goes idle, the
// client closes it or the server shuts down.
func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// A connection blocked in Read has to be woken some other way for
	// shutdown to make progress.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		data := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}

		req, err := dnsmsg.Unpack(data)
		if err != nil {
			return // a stream we can't parse can't be resynchronised
		}

		queryCtx, cancel := context.WithTimeout(ctx, s.queryTimeout())
		w := &tcpResponseWriter{conn: conn, clientUsedEDNS0: req.OPT() != nil}
		s.Handler.ServeDNS(queryCtx, w, req)
		cancel()
	}
}

type tcpResponseWriter struct {
	conn            net.Conn
	clientUsedEDNS0 bool
}

func (w *tcpResponseWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

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
	w.conn.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
	_, err = w.conn.Write(append(lenPrefix, packet...))
	return err
}
