//go:build windows

package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

type queryRemotePeer func(conn net.Conn) (string, error)

// TransparentProxy represents a transparent proxy server.
type TransparentProxy struct {
	socksEndpoint string
	socksUsername string
	socksPassword string
	listener      net.Listener
	cancel        context.CancelFunc

	queryRemotePeer queryRemotePeer
}

// NewTransparentProxy creates a new instance of TransparentProxy.
func NewTransparentProxy(socksEndpoint string, socksUsername, socksPassword string, queryRemotePeer queryRemotePeer) *TransparentProxy {
	return &TransparentProxy{
		socksEndpoint:   socksEndpoint,
		socksUsername:   socksUsername,
		socksPassword:   socksPassword,
		queryRemotePeer: queryRemotePeer,
	}
}

// Start starts the transparent proxy server.
func (tp *TransparentProxy) Start(ctx context.Context) error {
	var err error
	tp.listener, err = net.Listen("tcp", ":0")
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}
	defer tp.listener.Close()

	log.Printf("Transparent proxy listening on %s", tp.listener.Addr().String())

	ctx, tp.cancel = context.WithCancel(ctx)

	for {
		conn, err := tp.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("failed to accept connection: %v", err)
				continue
			}
		}

		go tp.handleConnection(conn)
	}
}

// GetLocalProxyPort returns the local proxy port.
func (tp *TransparentProxy) GetLocalProxyPort() uint16 {
	if tp.listener == nil {
		return 0
	}
	addr := tp.listener.Addr().(*net.TCPAddr)
	return uint16(addr.Port)
}

// handleConnection handles a new client connection that is redirected.
func (tp *TransparentProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Extract the original destination address from the connection
	dst, err := tp.queryRemotePeer(clientConn)
	if err != nil {
		log.Printf("failed to connect to remote host: %v", err)
		return
	}

	var remoteConn net.Conn
	remoteConn, err = tp.connectViaSocks5(dst)
	if err != nil {
		log.Printf("failed to connect to remote host: %v", err)
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	
	// Forward data between client and remote server
	go tp.forwardData(clientConn, remoteConn, &wg)
	go tp.forwardData(remoteConn, clientConn, &wg)

	wg.Wait()
}

// connectViaSocks5 connects to the remote host via SOCKS5 proxy.
func (tp *TransparentProxy) connectViaSocks5(dst string) (net.Conn, error) {
	auth := &proxy.Auth{
		User:     tp.socksUsername,
		Password: tp.socksPassword,
	}

	dialer, err := proxy.SOCKS5("tcp", tp.socksEndpoint, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	return dialer.Dial("tcp", dst)
}

// forwardData forwards data between source and destination connections.
func (tp *TransparentProxy) forwardData(src, dst net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src)
}

// Stop stops the transparent proxy server.
func (tp *TransparentProxy) Stop() {
	if tp.cancel != nil {
		tp.cancel()
	}
	if tp.listener != nil {
		tp.listener.Close()
	}
}
