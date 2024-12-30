//go:build windows

package ndisapi

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

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

// SetPacketFilterTable sets the static packet filter table for the Windows Packet Filter driver.
func (a *NdisApi) SetPacketFilterTable(packet *StaticFilterTable) error {
	var size uint32 = 0
	if packet != nil {
		size = uint32(unsafe.Sizeof(StaticFilterTable{})) + (packet.TableSize-1)*uint32(unsafe.Sizeof(StaticFilterEntry{}))
	}

	return a.DeviceIoControl(
		IOCTL_NDISRD_SET_PACKET_FILTERS,
		unsafe.Pointer(packet),
		size,
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// ResetPacketFilterTable resets the static packet filter table for the Windows Packet Filter driver.
func (a *NdisApi) ResetPacketFilterTable() error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_RESET_PACKET_FILTERS,
		nil,
		0,
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// GetPacketFilterTableSize retrieves the size of the static packet filter table from the Windows Packet Filter driver.
func (a *NdisApi) GetPacketFilterTableSize() (*uint32, error) {
	var tableSize uint32

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE,
		nil,
		0,
		unsafe.Pointer(&tableSize),
		uint32(unsafe.Sizeof(tableSize)),
		nil,
		nil,
	)

	if err != nil {
		return nil, err
	}

	return &tableSize, nil
}

// GetPacketFilterTable retrieves the static packet filter table from the Windows Packet Filter driver.
func (a *NdisApi) GetPacketFilterTable() (*StaticFilterTable, error) {
	var staticFilterTable StaticFilterTable

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS,
		nil,
		0,
		unsafe.Pointer(&staticFilterTable),
		uint32(unsafe.Sizeof(StaticFilterTable{}))+(staticFilterTable.TableSize-1)*uint32(unsafe.Sizeof(StaticFilterEntry{})),
		nil, // Bytes Returned
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &staticFilterTable, nil
}

// GetPacketFilterTableResetStats retrieves the static packet filter table and resets statistics for the Windows Packet Filter driver.
func (a *NdisApi) GetPacketFilterTableResetStats() (*StaticFilterTable, error) {
	var staticFilterTable StaticFilterTable

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
		nil,
		0,
		unsafe.Pointer(&staticFilterTable),
		uint32(unsafe.Sizeof(StaticFilterTable{}))+(staticFilterTable.TableSize-1)*uint32(unsafe.Sizeof(StaticFilterEntry{})),
		nil, // Bytes Returned
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &staticFilterTable, nil
}


// IsNdiswanInterfaces checks if the given adapter is an NDISWAN interface.
func (a *NdisApi) IsNdiswanInterfaces(adapterName, ndiswanName string) bool {
	isNdiswanInterface := false

	// TODO:

	return isNdiswanInterface
}

// IsNdiswanIP checks if the given adapter is an NDISWANIP interface.
func (a *NdisApi) IsNdiswanIP(adapterName string) bool {
	if a.IsWindows10OrGreater() && strings.Contains(adapterName, DEVICE_NDISWANIP) {
		return true
	}

	return a.IsNdiswanInterfaces(adapterName, REGSTR_COMPONENTID_NDISWANIP)
}

// IsNdiswanIPv6 checks if the given adapter is an NDISWANIPV6 interface.
func (a *NdisApi) IsNdiswanIPv6(adapterName string) bool {
	if a.IsWindows10OrGreater() && strings.Contains(adapterName, DEVICE_NDISWANIPV6) {
		return true
	}

	return a.IsNdiswanInterfaces(adapterName, REGSTR_COMPONENTID_NDISWANIPV6)
}

// IsNdiswanBh checks if the given adapter is an NDISWANBH interface.
func (a *NdisApi) IsNdiswanBh(adapterName string) bool {
	if a.IsWindows10OrGreater() && strings.Contains(adapterName, DEVICE_NDISWANBH) {
		return true
	}

	return a.IsNdiswanInterfaces(adapterName, REGSTR_COMPONENTID_NDISWANBH)
}
var mod = syscall.NewLazyDLL("kernel32.dll")
var proc = mod.NewProc("GetVersion")
// IsWindows10OrGreater checks if the operating system is Windows 10 or greater.
func (a *NdisApi) IsWindows10OrGreater() bool {
	version, _, _ := proc.Call()
	major := byte(version)
	minor := byte(version >> 8)

	return major > 6 || (major == 6 && minor >= 2)
}
