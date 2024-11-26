//go:build windows

package ndisapi

import (
	"net"
)

const (
	ETH_ALEN            = 6  /* Octets in one ethernet addr	 */
	ETHER_HEADER_LENGTH = 14 /* Ethernet header length */

	ARPHRD_ETHER  = 0x01
	ARPOP_REQUEST = 0x01
	ARPOP_REPLY   = 0x02

	ETH_P_IP     = 0x0800 /* Internet Protocol packet	*/
	ETH_P_IP_NET = 0x0008 /* Internet Protocol packet	network order*/
	ETH_P_RARP   = 0x8035 /* Reverse Addr Res packet	*/
	ETH_P_ARP    = 0x0806 /* Address Resolution packet	*/

	ETH_P_IPV6     = 0x86dd /* Internet Protocol V6 packet	*/
	ETH_P_IPV6_NET = 0xdd86 /* Internet Protocol V6 packet network order*/

	// Protocols
	IPPROTO_IP   = 0  /* dummy for IP */
	IPPROTO_ICMP = 1  /* control message protocol */
	IPPROTO_IGMP = 2  /* group management protocol */
	IPPROTO_GGP  = 3  /* gateway^2 (deprecated) */
	IPPROTO_TCP  = 6  /* tcp */
	IPPROTO_PUP  = 12 /* pup */
	IPPROTO_UDP  = 17 /* user datagram protocol *ETH_P_IP/
	   IPPROTO_IDP    = 22 /* xns idp */
	IPPROTO_ICMPV6 = 58 /* control message protocol v6*/
	IPPROTO_ND     = 77 /* UNOFFICIAL net disk proto */

	IPPROTO_RAW = 255 /* raw IP packet */
	IPPROTO_MAX = 256
)

// Ethernet Header
type EtherHeader struct {
	Dest   [ETH_ALEN]byte // destination eth addr
	Source [ETH_ALEN]byte // source ether addr
	Proto  uint16         // packet type ID field
}

// Address Resolution Protocol (ARP)
type ArpHeader struct {
	Hrd uint16 // format of hardware address
	Pro uint16 // format of protocol address
	Hln uint8  // length of hardware address
	Pln uint8  // length of protocol address
	Op  uint16 // ARP opcode (command)
}

type EthernetArp struct {
	Header                ArpHeader // fixed-size header
	SenderHardwareAddress [6]byte   // sender hardware address
	SenderProtocolAddress [4]byte   // sender protocol address
	TargetHardwareAddress [6]byte   // target hardware address
	TargetProtocolAddress [4]byte   // target protocol address
}

// IP Header in Little Endian
type IPHeader struct {
	VersionAndHeaderLength uint8   // version and header length packed into one byte
	ServiceType            uint8   // type of service
	TotalLength            uint16  // total length
	Identification         uint16  // identification
	FragmentOffset         uint16  // fragment offset field
	TTL                    uint8   // time to live
	Protocol               uint8   // protocol
	Checksum               uint16  // checksum
	SourceAddr             [4]byte // source address
	DestinationAddr        [4]byte // destination address
}

// Helper functions to extract and set the version and header length
func (h *IPHeader) Version() uint8 {
	return h.VersionAndHeaderLength >> 4
}

func (h *IPHeader) HeaderLength() uint8 {
	return h.VersionAndHeaderLength & 0x0F
}

func (h *IPHeader) SetVersion(version uint8) {
	h.VersionAndHeaderLength = (version << 4) | (h.VersionAndHeaderLength & 0x0F)
}

func (h *IPHeader) SetHeaderLength(headerLength uint8) {
	h.VersionAndHeaderLength = (h.VersionAndHeaderLength & 0xF0) | (headerLength & 0x0F)
}

// UDP header
type UdpHeader struct {
	SourcePort      uint16 // source port
	DestinationPort uint16 // destination port
	Length          uint16 // data length
	Checksum        uint16 // checksum
}

type TcpSeq uint32

// TCP header. Per RFC 793, September, 1981. In Little Endian
type TCPHeader struct {
	SourcePort     uint16 // source port
	DestPort       uint16 // destination port
	Sequence       TcpSeq // sequence number
	Acknowledgment TcpSeq // acknowledgement number
	OffsetX2       uint8  // data offset and (unused)
	Flags          uint8
	Window         uint16 // window
	Checksum       uint16 // checksum
	Urp            uint16 // urgent pointer
}

// Helper functions to extract and set the offset and X2 fields
func (h *TCPHeader) Offset() uint8 {
	return h.OffsetX2 >> 4
}

func (h *TCPHeader) X2() uint8 {
	return h.OffsetX2 & 0x0F
}

func (h *TCPHeader) SetOffset(offset uint8) {
	h.OffsetX2 = (offset << 4) | (h.OffsetX2 & 0x0F)
}

func (h *TCPHeader) SetX2(x2 uint8) {
	h.OffsetX2 = (h.OffsetX2 & 0xF0) | (x2 & 0x0F)
}

type PseudoHeader struct {
	SourceAddress net.IP
	DestAddress   net.IP
	Placeholder   uint8
	Protocol      uint8
	TcpLength     uint16
}

// IPv6 header format
type IPv6Header struct {
	ClassHi     uint8
	V           uint8
	FlowHi      uint8
	ClassLo     uint8
	FlowLo      uint16
	Len         uint16
	Next        uint8
	Hops        uint8
	Source      net.IP
	Destination net.IP
}

// IPv6 extension header format
type IPv6Extension struct {
	Next uint8
	Len  uint8
	Data [2]byte
}

type IPv6ExtFrag struct {
	Next     uint8
	Reserved uint8
	Offlg    uint16
	Ident    uint32
}

type MssTcpOptions struct {
	Type         uint8
	OptionLength uint8
	Value        uint16
}

// ICMP header
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
}

// ICMPv6 header
type ICMPv6Header struct {
	Type     uint8
	Code     uint8
	Checksum uint16
}

// DNS header
type DNSHeader struct {
	Id      uint16
	Flags   uint16
	Qdcount uint16
	Ancount uint16
	Nscount uint16
	Arcount uint16
}

// Resource record
type QrRecord struct {
	Type uint16
	Clas uint16
}

type ResRecord struct {
	Type     uint16
	Clas     uint16
	Ttl      uint32
	Rdlength uint16
}
