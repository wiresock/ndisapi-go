//go:build windows

package main

import (
	"net"
	"strconv"
	"sync"
	"unsafe"

	N "github.com/wiresock/ndisapi-go/netlib"

	A "github.com/wiresock/ndisapi-go"
)

type localRedirect struct {
	originalDestIP  net.IP
	originalSrcPort uint16
}

func newLocalRedirect(originalDestIP net.IP, originalSrcPort uint16) localRedirect {
	return localRedirect{
		originalDestIP:  originalDestIP,
		originalSrcPort: originalSrcPort,
	}
}

func (k localRedirect) String() string {
	return k.originalDestIP.String() + ":" + strconv.Itoa(int(k.originalSrcPort))
}

func (k localRedirect) Equal(other localRedirect) bool {
	return k.originalDestIP.Equal(other.originalDestIP) && k.originalSrcPort == other.originalSrcPort
}

type LocalRedirector struct {
	proxyPort             uint16
	redirectedConnections sync.Map
}

func NewLocalRedirector(proxyPort uint16) *LocalRedirector {
	redirector := &LocalRedirector{
		proxyPort: proxyPort,
	}

	return redirector
}

func (l *LocalRedirector) ProcessClientToServerPacket(packet *A.IntermediateBuffer, port uint16) bool {
	etherHeaderSize := int(unsafe.Sizeof(A.EtherHeader{}))
	if len(packet.Buffer) < etherHeaderSize {
		return false
	}

	etherHeader := (*A.EtherHeader)(unsafe.Pointer(&packet.Buffer[0])) // Ethernet header pointer
	ipProto := A.Ntohs(etherHeader.Proto)                              // IP Protocol pointer

	if ipProto != A.ETH_P_IP { // If it's not IP protocol version 4
		return false
	}

	ipHeaderSize := int(unsafe.Sizeof(A.IPHeader{}))
	if len(packet.Buffer) < etherHeaderSize+ipHeaderSize {
		return false
	}

	ipHeaderOffset := etherHeaderSize
	ipHeader := (*A.IPHeader)(unsafe.Pointer(&packet.Buffer[ipHeaderOffset])) // IP header pointer

	if ipHeader.Protocol != A.IPPROTO_TCP {
		return false
	}

	tcpHeaderSize := int(unsafe.Sizeof(A.TCPHeader{}))
	if len(packet.Buffer) < etherHeaderSize+ipHeaderSize+tcpHeaderSize {
		return false
	}

	tcpHeaderOffset := ipHeaderOffset + int(ipHeader.HeaderLength()*4)
	tcpHeader := (*A.TCPHeader)(unsafe.Pointer(&packet.Buffer[tcpHeaderOffset])) // TCP header pointer

	key := newLocalRedirect(ipHeader.DestinationAddr[:], tcpHeader.SourcePort)

	if (tcpHeader.Flags & (N.TH_SYN | N.TH_ACK)) == N.TH_SYN {
		if _, loaded := l.redirectedConnections.LoadOrStore(key.String(), tcpHeader.DestPort); loaded {
			return false
		}
	} else {
		_, exists := l.redirectedConnections.Load(key.String())
		if !exists {
			return false
		}

		if (tcpHeader.Flags & (N.TH_RST | N.TH_FIN)) != 0 {
			l.redirectedConnections.Delete(key.String())
		}
	}

	// 1. Swap Ethernet addresses
	etherHeader.Source, etherHeader.Dest = etherHeader.Dest, etherHeader.Source

	// 2. Swap IP addresses
	ipHeader.DestinationAddr, ipHeader.SourceAddr = ipHeader.SourceAddr, ipHeader.DestinationAddr

	tcpHeader.DestPort = port

	return true
}

func (l *LocalRedirector) ProcessServerToClientPacket(packet *A.IntermediateBuffer) bool {
	etherHeaderSize := int(unsafe.Sizeof(A.EtherHeader{}))
	if len(packet.Buffer) < etherHeaderSize {
		return false
	}

	etherHeader := (*A.EtherHeader)(unsafe.Pointer(&packet.Buffer[0])) // Ethernet header pointer
	ipProto := A.Ntohs(etherHeader.Proto)                              // IP Protocol pointer

	if ipProto != A.ETH_P_IP { // If it's not IP protocol version 4
		return false
	}

	ipHeaderSize := int(unsafe.Sizeof(A.IPHeader{}))
	if len(packet.Buffer) < etherHeaderSize+ipHeaderSize {
		return false
	}

	ipHeaderOffset := etherHeaderSize
	ipHeader := (*A.IPHeader)(unsafe.Pointer(&packet.Buffer[ipHeaderOffset])) // IP header pointer

	if ipHeader.Protocol != A.IPPROTO_TCP {
		return false
	}

	tcpHeaderSize := int(unsafe.Sizeof(A.TCPHeader{}))
	if len(packet.Buffer) < etherHeaderSize+ipHeaderSize+tcpHeaderSize {
		return false
	}

	tcpHeaderOffset := ipHeaderOffset + int(ipHeader.HeaderLength()*4)
	tcpHeader := (*A.TCPHeader)(unsafe.Pointer(&packet.Buffer[tcpHeaderOffset])) // TCP header pointer

	key := newLocalRedirect(ipHeader.DestinationAddr[:], tcpHeader.DestPort)
	it, exists := l.redirectedConnections.Load(key.String())
	if !exists {
		return false
	}

	tcpHeader.SourcePort = it.(uint16)

	if (tcpHeader.Flags & (N.TH_RST | N.TH_FIN)) != 0 {
		l.redirectedConnections.Delete(key.String())
	}

	// 1. Swap Ethernet addresses
	etherHeader.Source, etherHeader.Dest = etherHeader.Dest, etherHeader.Source

	// 2. Swap IP addresses
	ipHeader.DestinationAddr, ipHeader.SourceAddr = ipHeader.SourceAddr, ipHeader.DestinationAddr

	return true
}
