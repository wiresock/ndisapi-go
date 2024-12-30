//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket/layers"
	"github.com/wzshiming/socks5"
)

type queryTcpRemotePeer func(conn net.Conn) (net.IP, layers.TCPPort, error)
type queryUdpRemotePeer func(addr net.Addr) (net.IP, layers.UDPPort, error)

// TransparentProxy represents a transparent proxy server.
type TransparentProxy struct {
	port uint16

	socks5Dialer *socks5.Dialer

	tcpListener net.Listener
	udpListener *net.UDPConn

	cancel context.CancelFunc

	queryTcpRemotePeer queryTcpRemotePeer
	queryUdpRemotePeer queryUdpRemotePeer

	udpConnections map[string]net.Conn
	udpMutex       sync.Mutex
}

// NewTransparentProxy creates a new instance of TransparentProxy.
func NewTransparentProxy(
	localProxyPort uint16,
	socks5Dialer *socks5.Dialer,
	queryTcpRemotePeer queryTcpRemotePeer,
	queryUdpRemotePeer queryUdpRemotePeer,
) *TransparentProxy {
	return &TransparentProxy{
		port:               localProxyPort,
		socks5Dialer:       socks5Dialer,
		queryTcpRemotePeer: queryTcpRemotePeer,
		queryUdpRemotePeer: queryUdpRemotePeer,
		udpConnections:     make(map[string]net.Conn),
	}
}

// GetLocalTcpProxyPort returns the local proxy port.
func (tp *TransparentProxy) GetLocalTcpProxyPort() uint16 {
	if tp.tcpListener == nil {
		return 0
	}
	addr := tp.tcpListener.Addr().(*net.TCPAddr)
	return uint16(addr.Port)
}

// GetLocalUdpProxyPort returns the local proxy port.
func (tp *TransparentProxy) GetLocalUdpProxyPort() uint16 {
	if tp.udpListener == nil {
		return 0
	}
	addr := tp.udpListener.LocalAddr().(*net.UDPAddr)
	return uint16(addr.Port)
}

// Start starts the transparent proxy server.
func (tp *TransparentProxy) Start(ctx context.Context) error {
	var err error
	tp.tcpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", tp.port))
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}

	udpAddr := &net.UDPAddr{Port: int(tp.port)}
	tp.udpListener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}

	log.Printf("Transparent proxy listening on TCP %s and UDP %s", tp.tcpListener.Addr().String(), tp.udpListener.LocalAddr().String())

	ctx, tp.cancel = context.WithCancel(ctx)

	go tp.acceptTcpConnections(ctx)
	go tp.acceptUdpConnections(ctx)

	<-ctx.Done()

	return nil
}

// Stop stops the transparent proxy server.
func (tp *TransparentProxy) Stop() {
	if tp.cancel != nil {
		tp.cancel()
	}

	if tp.tcpListener != nil {
		tp.tcpListener.Close()
	}

	if tp.udpListener != nil {
		tp.udpListener.Close()
	}
}

func (tp *TransparentProxy) acceptTcpConnections(ctx context.Context) {
	for {
		conn, err := tp.tcpListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("failed to accept TCP connection: %v", err)
				continue
			}
		}
		go tp.handleTcpConnection(ctx, conn)
	}
}

func (tp *TransparentProxy) handleTcpConnection(_ context.Context, conn net.Conn) {
	defer conn.Close()

	dstIP, dstPort, err := tp.queryTcpRemotePeer(conn)
	if err != nil {
		log.Printf("failed to get destination address: %v", err)
		return
	}

	remoteConn, err := tp.socks5Dialer.Dial("tcp", fmt.Sprintf("%s:%d", dstIP, dstPort))
	if err != nil {
		log.Printf("failed to connect to remote host: %v", err)
		return
	}
	defer remoteConn.Close()

	go func() {
		_, _ = io.Copy(remoteConn, conn)
	}()
	_, _ = io.Copy(conn, remoteConn)
}

func (tp *TransparentProxy) acceptUdpConnections(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := tp.udpListener.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("failed to read UDP packet: %v", err)
				continue
			}
		}
		go tp.handleUdpPacket(buf[:n], clientAddr)
	}
}

func (tp *TransparentProxy) handleUdpPacket(packet []byte, addr net.Addr) {
	dstIP, dstPort, err := tp.queryUdpRemotePeer(addr)
	if err != nil {
		log.Printf("failed to get destination address: %v", err)
		return
	}

	localPort := addr.(*net.UDPAddr).Port

	localAddr := fmt.Sprintf("%s:%d", dstIP.String(), localPort)
	remoteAddr := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)

	tp.udpMutex.Lock()
	udpConn, exists := tp.udpConnections[localAddr]
	if !exists {
		udpConn, err = tp.socks5Dialer.Dial("udp", remoteAddr)
		if err != nil {
			tp.udpMutex.Unlock()
			log.Printf("failed to connect to remote host: %v", err)
			return
		}
		tp.udpConnections[localAddr] = udpConn

		// Start a goroutine to continuously read from the UDP connection
		go tp.readFromUdpConnection(udpConn, localAddr)
	}
	tp.udpMutex.Unlock()

	_, err = udpConn.Write(packet)
	if err != nil {
		log.Printf("failed to send UDP packet to remote host: %v", err)
		return
	}
}

func (tp *TransparentProxy) readFromUdpConnection(udpConn net.Conn, addr string) {
	buf := make([]byte, 65535)
	for {
		n, err := udpConn.Read(buf)
		if err != nil {
			log.Printf("failed to read UDP response from remote host: %v", err)
			return
		}

		tp.udpMutex.Lock()
		_, exists := tp.udpConnections[addr]
		tp.udpMutex.Unlock()

		if !exists {
			log.Printf("failed to find client address for client address: %v", addr)
			return
		}

		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Fatalf("Failed to resolve UDP address: %v", err)
			return
		}

		_, err = tp.udpListener.WriteTo(buf[:n], udpAddr)
		if err != nil {
			log.Printf("failed to send UDP response to client: %v", err)
			return
		}
	}
}
