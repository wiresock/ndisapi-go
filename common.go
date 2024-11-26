//go:build windows

package ndisapi

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// common constants
const (
	NDISRD_VERSION       = 0x04033000
	NDISRD_MAJOR_VERSION = 0x0003
	NDISRD_MINOR_VERSION = 0x0403

	// Common strings set
	DRIVER_NAME_A   = "NDISRD"
	DRIVER_NAME_U   = "NDISRD"
	DEVICE_NAME     = "\\Device\\NDISRD"
	SYMLINK_NAME    = "\\DosDevices\\NDISRD"
	WIN9X_REG_PARAM = "System\\CurrentControlSet\\Services\\VxD\\ndisrd\\Parameters"
	WINNT_REG_PARAM = "SYSTEM\\CurrentControlSet\\Services\\ndisrd\\Parameters"

	FILTER_FRIENDLY_NAME = "WinpkFilter NDIS LightWeight Filter"
	FILTER_UNIQUE_NAME   = "{CD75C963-E19F-4139-BC3B-14019EF72F19}"
	FILTER_SERVICE_NAME  = "NDISRD"

	ADAPTER_NAME_SIZE = 256
	ADAPTER_LIST_SIZE = 32
	ETHER_ADDR_LENGTH = 6
	MAX_ETHER_FRAME   = 1514

	// Adapter flags
	MSTCP_FLAG_SENT_TUNNEL = 0x00000001 // Receive packets sent by MSTCP
	MSTCP_FLAG_RECV_TUNNEL = 0x00000002 // Receive packets instead MSTCP
	MSTCP_FLAG_SENT_LISTEN = 0x00000004 // Receive packets sent by MSTCP, original ones delivered to the network
	MSTCP_FLAG_RECV_LISTEN = 0x00000008 // Receive packets received by MSTCP

	MSTCP_FLAG_FILTER_DIRECT = 0x00000010 // In promiscuous mode TCP/IP stack receives all
	// all packets in the ethernet segment, to prevent this set this flag
	// All packets with destination MAC different from FF-FF-FF-FF-FF-FF and
	// network interface current MAC will be blocked

	// By default loopback packets are passed to original MSTCP handlers without processing,
	// to change this behavior use the flags below
	MSTCP_FLAG_LOOPBACK_FILTER = 0x00000020 // FilterActionPass loopback packet for processing
	MSTCP_FLAG_LOOPBACK_BLOCK  = 0x00000040 // Silently drop loopback packets, this flag
	// is recommended for usage in combination with
	// promiscuous mode

	// Device flags for intermediate buffer
	PACKET_FLAG_ON_SEND    = 0x00000001
	PACKET_FLAG_ON_RECEIVE = 0x00000002
)
const (
	MaximumPacketBlock = 510
	MaximumBlockNum = 10
)

// Handle is equivalent to HANDLE to store windows native handle
// using windows.Handle will not help as its type is uintptr which we don't want that
type Handle [8]byte

// Packet actions
type FilterAction uint32

const (
	FilterActionPass FilterAction = iota
	FilterActionDrop
	FilterActionRedirect
	FilterActionPassRedirect
	FilterActionDropRedirect
)

type PacketDirection int

const (
	PacketDirectionIn PacketDirection = iota
	PacketDirectionOut
	PacketDirectionBoth
)

// TcpAdapterList structure used for requesting information about currently bound TCPIP adapters
type TcpAdapterList struct {
	AdapterCount      uint32                                     // Number of adapters
	AdapterNameList   [ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE]byte // Array of adapter names
	AdapterHandle     [ADAPTER_LIST_SIZE]Handle                  // Array of adapter handles, these are key handles for any adapter relative operation
	AdapterMediumList [ADAPTER_LIST_SIZE]uint32                  // List of adapter mediums
	CurrentAddress    [ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH]byte // current (configured) ethernet address
	MTU               [ADAPTER_LIST_SIZE]uint16                  // current adapter MTU
}

// IntermediateBuffer contains packet buffer, packet NDIS flags, WinpkFilter specific flags
type IntermediateBuffer struct {
	Union       [16]byte
	DeviceFlags uint32
	Length      uint32
	Flags       uint32 // NDIS_PACKET flags
	M8021q      uint32 // 802.1q tag
	FilterID    uint32
	Reserved    [4]uint32
	Buffer      [MAX_ETHER_FRAME]byte
}

// EthernetPacket is a container for IntermediateBuffer pointer
// This structure can be extended in the future versions
type EthernetPacket struct {
	Buffer *IntermediateBuffer
}

// EtherRequest used for passing the "read packet" request to driver
type EtherRequest struct {
	AdapterHandle  Handle
	EthernetPacket EthernetPacket
}

// EtherMultiRequest used for passing the "read packet" request to driver
type EtherMultiRequest struct {
	AdapterHandle   Handle
	PacketsNumber   uint32
	PacketsSuccess  uint32
	EthernetPackets [MaximumPacketBlock]EthernetPacket
}

// AdapterMode used for setting adapter mode
type AdapterMode struct {
	AdapterHandle Handle
	Flags         uint32
}

// AdapterEvent used for setting up the event which driver sets once having packet in the queue for the processing
type AdapterEvent struct {
	AdapterHandle Handle
	Event         windows.Handle
}

// PacketOidData used for passing NDIS_REQUEST to driver
type PacketOidData struct {
	AdapterHandle Handle
	Oid           uint32
	Length        uint32
	Data          [1]byte
}

// RASLinkInfo represents information for RAS links
type RASLinkInfo struct {
	// Zero indicates no change from the speed returned when the protocol called NdisRequest with OID_GEN_LINK_SPEED.
	LinkSpeed uint32 // Link speed in units of 100 bps

	// Specifies the maximum number of bytes per packet that the protocol can send over the network.
	// Zero indicates no change from the value returned when the protocol called NdisRequest with OID_GEN_MAXIMUM_TOTAL_SIZE.
	MaximumTotalSize uint32 // Maximum number of bytes per packet

	// Represents the address of the remote node on the link in Ethernet-style format. NDISWAN supplies this value.
	RemoteAddress net.HardwareAddr // Remote node address in Ethernet format

	// Represents the protocol-determined context for indications on this link in Ethernet-style format.
	LocalAddress net.HardwareAddr // Local node address in Ethernet format

	ProtocolBufferLength uint32 // Number of bytes in protocol buffer
	// Containing protocol-specific information supplied by a higher-level component that makes connections through NDISWAN
	// to the appropriate protocol(s). Maximum observed size is 600 bytes on Windows Vista, 1200 on Windows 10
	ProtocolBuffer [2048]byte // protocol-specific information
}

// RASLinks holds a collection of RAS link info
type RASLinks struct {
	NumberOfLinks uint32
	RASLinks      [256]RASLinkInfo
}

//
// Packet filter definitions
//

// Eth8023Filter represents Ethernet 802.3 filter type
type Eth8023Filter struct {
	ValidFields uint32
	SrcAddress  net.HardwareAddr
	DestAddress net.HardwareAddr
	Protocol    uint16
	Padding     uint16
}

// IPv4Subnet represents an IPv4 address with subnet mask
type IPv4Subnet struct {
	IP     uint32
	IPMask uint32
}

// IPv4Range represents an IP range in IPv4
type IPv4Range struct {
	StartIP uint32
	EndIP   uint32
}

const (
	IP_SUBNET_V4_TYPE = 0x00000001
	IP_RANGE_V4_TYPE  = 0x00000002
)

// IPv4Address represents an IPv4 address with type
type IPv4Address struct {
	AddressType uint32
	Subnet      IPv4Subnet
	Range       IPv4Range
}

func IPv4AddressFromIP(ip net.IP) IPv4Address {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return IPv4Address{}
	}

	mask := ip.DefaultMask()
	ipMask := binary.BigEndian.Uint32(mask)

	return IPv4Address{
		AddressType: IP_SUBNET_V4_TYPE,
		Subnet: IPv4Subnet{
			IP:     Htonl(binary.BigEndian.Uint32(ipv4)),
			IPMask: Htonl(ipMask),
		},
		Range: IPv4Range{
			StartIP: Htonl(binary.BigEndian.Uint32(ipv4)),
			EndIP:   Htonl(binary.BigEndian.Uint32(ipv4)),
		},
	}
}

// IPv4Filter represents an IPv4 filter type
type IPv4Filter struct {
	ValidFields uint32
	SrcAddress  IPv4Address
	DestAddress IPv4Address
	Protocol    uint8
	Padding     [3]uint8
}

// IPv6Subnet represents an IPv6 address with subnet mask
type IPv6Subnet struct {
	IP     [16]byte
	IPMask [16]byte
}

// IPv6Range represents an IPv6 address range
type IPv6Range struct {
	StartIP [16]byte
	EndIP   [16]byte
}

// IPv6Address represents an IPv6 address with type
type IPv6Address struct {
	AddressType uint32
	Subnet      IPv6Subnet
	Range       IPv6Range
}

// IPv6Filter represents an IPv6 filter type
type IPv6Filter struct {
	ValidFields uint32
	SrcAddress  IPv6Address
	DestAddress IPv6Address
	Protocol    uint8
	Padding     [3]uint8
}

// PortRange represents a range of ports
type PortRange struct {
	StartRange uint16
	EndRange   uint16
}

// TCPUDPFilter represents TCP and UDP filter criteria
type TCPUDPFilter struct {
	ValidFields uint32
	SourcePort  PortRange
	DestPort    PortRange
	TCPFlags    uint8
	Padding     [3]uint8
}

// ByteRange represents a range of bytes
type ByteRange struct {
	StartRange uint8
	EndRange   uint8
}

// ICMPFilter represents an ICMP filter criteria
type ICMPFilter struct {
	ValidFields uint32
	TypeRange   ByteRange
	CodeRange   ByteRange
}

// DataLinkLayerFilter represents data link layer filter level
type DataLinkLayerFilter struct {
	UnionSelector uint32
	Eth8023Filter Eth8023Filter
}

// NetworkLayerFilter represents network layer filter level
type NetworkLayerFilter struct {
	UnionSelector uint32
	IPv4          IPv4Filter
	IPv6          IPv6Filter
}

// TransportLayerFilter represents transport layer filter level
type TransportLayerFilter struct {
	UnionSelector uint32
	TCPUDP        TCPUDPFilter
	ICMP          ICMPFilter
}

// StaticFilterEntry defines a static filter entry
type StaticFilterEntry struct {
	Adapter        Handle
	DirectionFlags uint32
	FilterAction   FilterAction
	ValidFields    uint32

	LastReset  uint32
	PacketsIn  uint64
	BytesIn    uint64
	PacketsOut uint64
	BytesOut   uint64

	DataLinkFilter  DataLinkLayerFilter
	NetworkFilter   NetworkLayerFilter
	TransportFilter TransportLayerFilter
}

// StaticFilterTable represents a table of static filters
type StaticFilterTable struct {
	TableSize     uint32
	Padding       uint32
	StaticFilters []StaticFilterEntry
}

//
// WinpkFilter fast I/O definitions
//

// FastIOWriteUnion represents the interface for union-type values in Fast IO Write operations.
type FastIOWriteUnion interface {
	IsFastIOWriteUnion() // Marker method to fulfill the interface contract.
}

// SplitFields provides individual fields within FastIOWriteUnion.
type SplitFields struct {
	NumberOfPackets     uint16
	WriteInProgressFlag uint16
}

// JoinField provides the combined field within FastIOWriteUnion.
type JoinField struct {
	Join uint32
}

// IsFastIOWriteUnion provides a marker method for the SplitFields type.
func (s SplitFields) IsFastIOWriteUnion() {}

// IsFastIOWriteUnion provides a marker method for the JoinField type.
func (j JoinField) IsFastIOWriteUnion() {}

// FastIOSectionHeader defines the header for a fast I/O section.
type FastIOSectionHeader struct {
	FastIOWrite        FastIOWriteUnion
	ReadInProgressFlag uint32
}

// FastIOSection represents a section containing intermediate buffers for fast I/O.
type FastIOSection struct {
	FastIOHeader  FastIOSectionHeader
	FastIOPackets []IntermediateBuffer // Assumes IntermediateBuffer is defined elsewhere
}

// InitializeFastIOParams defines parameters for initializing a fast I/O section.
type InitializeFastIOParams struct {
	HeaderPtr *FastIOSection
	DataSize  uint32
}

//
// Unsorted Read/Send packets
//

// UnsortedReadSendRequest represents a request for unsorted read/send packets
type UnsortedReadSendRequest struct {
	Packets    []*IntermediateBuffer
	PacketsNum uint32
}

// IOCTL Codes For NDIS Packet redirect Driver
const (
	FILE_DEVICE_NDISRD = 0x00008300
	NDISRD_IOCTL_INDEX = 0x830
)

// from winioctl.h
const (
	METHOD_BUFFERED = 0
	FILE_ANY_ACCESS = 0
)

const (
	IOCTL_NDISRD_GET_VERSION                     = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | (NDISRD_IOCTL_INDEX << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_TCPIP_INTERFACES            = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 1) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER          = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 2) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_MSTCP            = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 3) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_READ_PACKET                     = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 4) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_ADAPTER_MODE                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 5) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE             = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 6) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_EVENT                       = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 7) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_NDIS_SET_REQUEST                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 8) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_NDIS_GET_REQUEST                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 9) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_WAN_EVENT                   = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 10) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_ADAPTER_EVENT               = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 11) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_ADAPTER_QUEUE_SIZE              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 12) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_ADAPTER_MODE                = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 13) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_PACKET_FILTERS              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 14) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_RESET_PACKET_FILTERS            = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 15) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE    = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 16) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_PACKET_FILTERS              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 17) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS  = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 18) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_GET_RAS_LINKS                   = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 19) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER         = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 20) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP           = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 21) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_READ_PACKETS                    = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 22) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT      = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 23) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_INITIALIZE_FAST_IO              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 24) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_READ_PACKETS_UNSORTED           = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 25) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 26) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED   = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 27) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION      = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 28) << 2) | METHOD_BUFFERED
	IOCTL_NDISRD_QUERY_IB_POOL_SIZE              = (FILE_DEVICE_NDISRD << 16) | (FILE_ANY_ACCESS << 14) | ((NDISRD_IOCTL_INDEX + 29) << 2) | METHOD_BUFFERED
)

func Ntohl(i uint32) uint32 {
	return binary.BigEndian.Uint32((*(*[4]byte)(unsafe.Pointer(&i)))[:])
}

func Htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func Ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&i)))[:])
}

func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
