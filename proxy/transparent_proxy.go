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

type TransparentProxy struct {
	listenAddr    string
	socksEndpoint string
	socksUsername string
	socksPassword string
	listener      net.Listener
	cancel        context.CancelFunc

	queryRemotePeer queryRemotePeer
}

func NewTransparentProxy(listenAddr, socksEndpoint string, socksUsername, socksPassword string, queryRemotePeer queryRemotePeer) *TransparentProxy {
	return &TransparentProxy{
		listenAddr:      listenAddr,
		socksEndpoint:   socksEndpoint,
		socksUsername:   socksUsername,
		socksPassword:   socksPassword,
		queryRemotePeer: queryRemotePeer,
	}
}

func (tp *TransparentProxy) Start(ctx context.Context) error {
	var err error
	tp.listener, err = net.Listen("tcp", tp.listenAddr)
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

func (tp *TransparentProxy) GetLocalProxyPort() uint16 {
	if tp.listener == nil {
		return 0
	}
	addr := tp.listener.Addr().(*net.TCPAddr)
	return uint16(addr.Port)
}

func (tp *TransparentProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Extract the original destination address from the connection
	dst, err := tp.queryRemotePeer(clientConn)
	if err != nil {
		log.Printf("failed to connect to remote host: %v", err)
		return
	}

	var remoteConn net.Conn
	if tp.socksEndpoint != "" {
		remoteConn, err = tp.connectViaSocks5(dst)
	} else {
		remoteConn, err = net.Dial("tcp", dst)
	}
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

func (tp *TransparentProxy) forwardData(src, dst net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src)
}

func (tp *TransparentProxy) Stop() {
	if tp.cancel != nil {
		tp.cancel()
	}
	if tp.listener != nil {
		tp.listener.Close()
	}
}
