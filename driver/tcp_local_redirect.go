//go:build windows

package driver

import (
	"sync"
	"time"
	"unsafe"

	N "github.com/amir-devman/ndisapi-go/netlib"

	A "github.com/amir-devman/ndisapi-go"
)

type timestampEndpoint struct {
	endpoint  uint16
	timestamp time.Time
}

type TcpLocalRedirector struct {
	redirectedConnections sync.Map
}

func NewTcpLocalRedirector() *TcpLocalRedirector {
	return &TcpLocalRedirector{}
}

func (l *TcpLocalRedirector) ProcessClientToServerPacket(packet *A.IntermediateBuffer, port uint16) bool {
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
		timestamp := timestampEndpoint{
			endpoint:  tcpHeader.DestPort,
			timestamp: time.Now(),
		}

		if _, loaded := l.redirectedConnections.LoadOrStore(key.String(), timestamp); loaded {
			return false
		}
	} else {
		it, exists := l.redirectedConnections.Load(key.String())
		if ; !exists {
			return false
		}

		if (tcpHeader.Flags & (N.TH_RST | N.TH_FIN)) != 0 {
			l.redirectedConnections.Delete(key.String())
		} else {
			timestamp := it.(timestampEndpoint)
			timestamp.timestamp = time.Now()
			l.redirectedConnections.Store(key.String(), timestamp)
		}
	}

	// 1. Swap Ethernet addresses
	etherHeader.Source, etherHeader.Dest = etherHeader.Dest, etherHeader.Source

	// 2. Swap IP addresses
	ipHeader.DestinationAddr, ipHeader.SourceAddr = ipHeader.SourceAddr, ipHeader.DestinationAddr

	tcpHeader.DestPort = port

	A.RecalculateTCPChecksum(packet)
	A.RecalculateIPChecksum(packet)

	return true
}

func (l *TcpLocalRedirector) ProcessServerToClientPacket(packet *A.IntermediateBuffer) bool {
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
	timestamp := it.(timestampEndpoint)

	tcpHeader.SourcePort = timestamp.endpoint

	if (tcpHeader.Flags & (N.TH_RST | N.TH_FIN)) != 0 {
		l.redirectedConnections.Delete(key.String())
	} else {
		timestamp.timestamp = time.Now()
		l.redirectedConnections.Store(key.String(), timestamp)
	}

	// 1. Swap Ethernet addresses
	etherHeader.Source, etherHeader.Dest = etherHeader.Dest, etherHeader.Source

	// 2. Swap IP addresses
	ipHeader.DestinationAddr, ipHeader.SourceAddr = ipHeader.SourceAddr, ipHeader.DestinationAddr

	A.RecalculateTCPChecksum(packet)
	A.RecalculateIPChecksum(packet)

	return true
}
