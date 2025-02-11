//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

type queryRemotePeer func(conn net.Conn) (string, error)

// HttpProxy represents a transparent proxy server.
type HttpProxy struct {
	port uint16

	endpoint string
	username string
	password string
	listener net.Listener
	cancel   context.CancelFunc

	queryRemotePeer queryRemotePeer
}

// NewHttpProxy creates a new instance of HttpProxy.
// a transparent proxy that forwards traffic to a remote host via HTTP proxy.
func NewHttpProxy(localProxyPort uint16, endpoint string, username, password string, queryRemotePeer queryRemotePeer) *HttpProxy {
	return &HttpProxy{
		port: localProxyPort,

		endpoint:        endpoint,
		username:        username,
		password:        password,
		queryRemotePeer: queryRemotePeer,
	}
}

// Start starts the transparent proxy server.
func (tp *HttpProxy) Start(ctx context.Context) error {
	var err error
	tp.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", tp.port))
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}

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
func (tp *HttpProxy) GetLocalProxyPort() uint16 {
	if tp.listener == nil {
		return 0
	}
	addr := tp.listener.Addr().(*net.TCPAddr)
	return uint16(addr.Port)
}

// handleConnection handles a new client connection that is redirected.
func (tp *HttpProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Extract the original destination address from the connection
	dst, err := tp.queryRemotePeer(clientConn)
	if err != nil {
		log.Printf("failed to connect to remote host: %v", err)
		return
	}

	var remoteConn net.Conn
	remoteConn, err = tp.connectViaHTTP(dst)
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

// connectViaHTTP connects to the remote host via HTTP proxy.
func (tp *HttpProxy) connectViaHTTP(dst string) (net.Conn, error) {
	proxyURL := fmt.Sprintf("%s", tp.endpoint)
	proxy, err := net.Dial("tcp", proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP proxy: %v", err)
	}

	auth := ""
	if tp.username != "" && tp.password != "" {
		auth = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(tp.username+":"+tp.password)) + "\r\n"
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", dst, dst, auth)
	_, err = proxy.Write([]byte(req))
	if err != nil {
		proxy.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %v", err)
	}

	resp := make([]byte, 4096)
	n, err := proxy.Read(resp)
	if err != nil {
		proxy.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %v", err)
	}

	if !strings.Contains(string(resp[:n]), "200 Connection established") {
		proxy.Close()
		return nil, fmt.Errorf("failed to establish connection: %s", string(resp[:n]))
	}

	return proxy, nil
}

// forwardData forwards data between source and destination connections.
func (tp *HttpProxy) forwardData(src, dst net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src)
	// Close connections when TCP connection has reset or finished
	if tcpConn, ok := src.(*net.TCPConn); ok {
		tcpConn.CloseRead()
	}
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}
}

// Stop stops the transparent proxy server.
func (tp *HttpProxy) Stop() {
	if tp.cancel != nil {
		tp.cancel()
	}
	if tp.listener != nil {
		tp.listener.Close()
	}
}
