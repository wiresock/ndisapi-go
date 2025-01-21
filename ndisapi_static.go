//go:build windows

package ndisapi

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

const RAS_LINK_BUFFER_LENGTH = 2048

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
	ProtocolBuffer [RAS_LINK_BUFFER_LENGTH]byte // protocol-specific information
}

const RAS_LINKS_MAX = 256

// RASLinks holds a collection of RAS link info
type RASLinks struct {
	NumberOfLinks uint32
	RASLinks      [RAS_LINKS_MAX]RASLinkInfo
}

// Static packet filter definitions

const (
	ETH_802_3_SRC_ADDRESS  = 0x00000001
	ETH_802_3_DEST_ADDRESS = 0x00000002
	ETH_802_3_PROTOCOL     = 0x00000004
)

// Eth8023Filter represents Ethernet 802.3 filter type
type Eth8023Filter struct {
	ValidFields        uint32
	SourceAddress      [ETHER_ADDR_LENGTH]byte
	DestinationAddress [ETHER_ADDR_LENGTH]byte
	Protocol           uint16
	Padding            uint16
}

const (
	IP_SUBNET_V4_TYPE = 0x00000001
	IP_RANGE_V4_TYPE  = 0x00000002
)

type IPv4Subnet struct {
	IP     uint32
	IPMask uint32
}

type IPv4Range struct {
	StartIP uint32
	EndIP   uint32
}

type IPv4Address struct {
	AddressType uint32
	union       [unsafe.Sizeof(IPv4Range{})]byte // To ensure the struct is packed exactly like the C++ union
}

func (a *IPv4Address) SetSubnet(subnet IPv4Subnet) {
	a.AddressType = IP_SUBNET_V4_TYPE
	copy(a.union[:], (*[unsafe.Sizeof(subnet)]byte)(unsafe.Pointer(&subnet))[:])
}

func (a *IPv4Address) SetRange(rng IPv4Range) {
	a.AddressType = IP_RANGE_V4_TYPE
	copy(a.union[:], (*[unsafe.Sizeof(rng)]byte)(unsafe.Pointer(&rng))[:])
}

func (a *IPv4Address) GetSubnet() *IPv4Subnet {
	if a.AddressType != IP_SUBNET_V4_TYPE {
		return nil
	}
	return (*IPv4Subnet)(unsafe.Pointer(&a.union[0]))
}

func (a *IPv4Address) GetRange() *IPv4Range {
	if a.AddressType != IP_RANGE_V4_TYPE {
		return nil
	}
	return (*IPv4Range)(unsafe.Pointer(&a.union[0]))
}

func IPv4AddressFromIP(ipNet net.IPNet) *IPv4Address {
	if ipNet.IP == nil {
		return nil
	}

	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return nil
	}

	mask := ipNet.Mask
	ipMask := binary.LittleEndian.Uint32(mask)

	subnet := IPv4Subnet{
		IP:     binary.LittleEndian.Uint32(ipv4),
		IPMask: ipMask,
	}

	addr := &IPv4Address{}
	addr.SetSubnet(subnet)
	return addr
}

func IPv4AddressToIPNet(addr *IPv4Address) net.IPNet {
	switch addr.AddressType {
	case IP_SUBNET_V4_TYPE:
		subnet := addr.GetSubnet()
		if subnet == nil {
			return net.IPNet{}
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, subnet.IP)
		mask := make(net.IPMask, 4)
		binary.LittleEndian.PutUint32(mask, subnet.IPMask)
		return net.IPNet{IP: ip, Mask: mask}
	case IP_RANGE_V4_TYPE:
		rng := addr.GetRange()
		if rng == nil {
			return net.IPNet{}
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, rng.StartIP)
		mask := net.CIDRMask(32, 32) // Assuming a full mask for the range
		return net.IPNet{IP: ip, Mask: mask}
	default:
		return net.IPNet{}
	}
}

const (
	IP_V4_FILTER_SRC_ADDRESS  = 0x00000001
	IP_V4_FILTER_DEST_ADDRESS = 0x00000002
	IP_V4_FILTER_PROTOCOL     = 0x00000004
)

// IPv4Filter represents an IPv4 filter type
type IPv4Filter struct {
	ValidFields        uint32
	SourceAddress      IPv4Address
	DestinationAddress IPv4Address
	Protocol           uint8
	Padding            [3]uint8
}

const (
	IP_SUBNET_V6_TYPE = 0x00000001
	IP_RANGE_V6_TYPE  = 0x00000002
)

// IPv6AddressType represents the type of IPv6 address (subnet or range)
type IPv6AddressType uint32

const (
	IPv6AddressTypeSubnet IPv6AddressType = IP_SUBNET_V6_TYPE
	IPv6AddressTypeRange  IPv6AddressType = IP_RANGE_V6_TYPE
)

// IPv6Address is an interface for IPv6 address types
type IPv6Address struct {
	AddressType uint32
	union       [unsafe.Sizeof(IPv6Range{})]byte // To ensure the struct is packed exactly like the C++ union
}

func (a *IPv6Address) SetSubnet(subnet IPv6Subnet) {
	a.AddressType = IP_SUBNET_V6_TYPE
	copy(a.union[:], (*[unsafe.Sizeof(subnet)]byte)(unsafe.Pointer(&subnet))[:])
}

func (a *IPv6Address) SetRange(rng IPv6Range) {
	a.AddressType = IP_RANGE_V6_TYPE
	copy(a.union[:], (*[unsafe.Sizeof(rng)]byte)(unsafe.Pointer(&rng))[:])
}

func (a *IPv6Address) GetSubnet() *IPv6Subnet {
	if a.AddressType != IP_SUBNET_V6_TYPE {
		return nil
	}
	return (*IPv6Subnet)(unsafe.Pointer(&a.union[0]))
}

func (a *IPv6Address) GetRange() *IPv6Range {
	if a.AddressType != IP_RANGE_V6_TYPE {
		return nil
	}
	return (*IPv6Range)(unsafe.Pointer(&a.union[0]))
}

type IPv6 = [16]byte

// IPv6Subnet represents an IPv6 address with subnet mask
type IPv6Subnet struct {
	IP     IPv6
	IPMask IPv6
}

// GetType returns the type of IPv6 address (subnet)
func (s IPv6Subnet) GetType() IPv6AddressType {
	return IPv6AddressTypeSubnet
}

// IPv6Range represents an IP range in IPv6
type IPv6Range struct {
	StartIP IPv6
	EndIP   IPv6
}

// GetType returns the type of IPv6 address (range)
func (r IPv6Range) GetType() IPv6AddressType {
	return IPv6AddressTypeRange
}

// IPv6SubnetOrRange represents an IPv6 address which can be either a subnet or a range
type IPv6SubnetOrRange struct {
	AddressType IPv6AddressType
	Address     net.IP // To ensure the struct is packed exactly like the C++ union
}

// SetSubnet sets the IPv6SubnetOrRange to a subnet
func (a *IPv6SubnetOrRange) SetSubnet(subnet IPv6Subnet) {
	a.AddressType = IPv6AddressTypeSubnet
	copy(a.Address[:], (*[unsafe.Sizeof(subnet)]byte)(unsafe.Pointer(&subnet))[:])
}

// SetRange sets the IPv6SubnetOrRange to a range
func (a *IPv6SubnetOrRange) SetRange(rng IPv4Range) {
	a.AddressType = IPv6AddressTypeRange
	copy(a.Address[:], (*[unsafe.Sizeof(rng)]byte)(unsafe.Pointer(&rng))[:])
}

// IPv6AddressFromIP converts a net.IP to an IPv6Address.
func IPv6AddressFromIP(ipNet net.IPNet) *IPv6Address {
	if ipNet.IP == nil {
		return nil
	}

	ipv6 := ipNet.IP.To16()
	if ipv6 == nil {
		return nil
	}

	mask := ipNet.Mask
	ipMask := make([]byte, 16)
	copy(ipMask, mask)

	subnet := IPv6Subnet{
		IP:     [16]byte{},
		IPMask: [16]byte{},
	}
	copy(subnet.IP[:], ipv6)
	copy(subnet.IPMask[:], ipMask)

	addr := &IPv6Address{}
	addr.SetSubnet(subnet)
	return addr
}

// IPv6AddressToIP converts an IPv6Address to a net.IP.
func IPv6AddressToIPNet(addr *IPv6Address) net.IPNet {
	switch addr.AddressType {
	case IP_SUBNET_V6_TYPE:
		subnet := addr.GetSubnet()
		if subnet == nil {
			return net.IPNet{}
		}
		ip := make(net.IP, 16)
		copy(ip, subnet.IP[:])
		mask := make(net.IPMask, 16)
		copy(mask, subnet.IPMask[:])
		return net.IPNet{IP: ip, Mask: mask}
	case IP_RANGE_V6_TYPE:
		rng := addr.GetRange()
		if rng == nil {
			return net.IPNet{}
		}
		ip := make(net.IP, 16)
		copy(ip, rng.StartIP[:])
		mask := net.CIDRMask(128, 128) // Assuming a full mask for the range
		return net.IPNet{IP: ip, Mask: mask}
	default:
		return net.IPNet{}
	}
}

const (
	IP_V6_FILTER_SRC_ADDRESS  = 0x00000001
	IP_V6_FILTER_DEST_ADDRESS = 0x00000002
	IP_V6_FILTER_PROTOCOL     = 0x00000004
)

// IPv6Filter represents an IPv6 filter type
type IPv6Filter struct {
	ValidFields        uint32
	SourceAddress      IPv6Address
	DestinationAddress IPv6Address
	Protocol           uint8
	Padding            [3]uint8
}

// PortRange represents a range of ports
type PortRange struct {
	StartRange uint16
	EndRange   uint16
}

const (
	TCPUDP_SRC_PORT  = 0x00000001
	TCPUDP_DEST_PORT = 0x00000002
	TCPUDP_TCP_FLAGS = 0x00000004
)

// TCPUDPFilter represents TCP and UDP filter criteria
type TCPUDPFilter struct {
	ValidFields     uint32
	SourcePort      PortRange
	DestinationPort PortRange
	TCPFlags        uint8
	Padding         [3]uint8
}

// ByteRange represents a range of bytes
type ByteRange struct {
	StartRange uint8
	EndRange   uint8
}

const (
	ICMP_TYPE = 0x00000001
	ICMP_CODE = 0x00000002
)

// ICMPFilter represents an ICMP filter criteria
type ICMPFilter struct {
	ValidFields uint32
	TypeRange   ByteRange
	CodeRange   ByteRange
}

// LayerFilter represents the type of IPv6 address (subnet or range)
type LayerFilter uint32

const (
	LayerFilterDataLink LayerFilter = iota
	LayerFilterNetwork
	LayerFilterTransport
)

const ETH_802_3 = 0x00000001

// DataLinkLayerFilter represents data link layer filter level
type DataLinkLayerFilter struct {
	Selector      uint32
	Eth8023Filter Eth8023Filter
}

const (
	IPV4 = 0x00000001
	IPV6 = 0x00000002
)

// NetworkLayerFilter represents network layer filter level
type NetworkLayerFilter struct {
	Selector uint32
	union    [unsafe.Sizeof(IPv6Filter{})]byte // To ensure the struct is packed exactly like the C++ union
}

// SetIPv4 sets the NetworkLayerFilter to an IPv4 filter
func (n *NetworkLayerFilter) SetIPv4(filter IPv4Filter) {
	n.Selector = IPV4
	copy(n.union[:], (*[unsafe.Sizeof(filter)]byte)(unsafe.Pointer(&filter))[:])
}

// SetIPv6 sets the NetworkLayerFilter to an IPv6 filter
func (n *NetworkLayerFilter) SetIPv6(filter IPv6Filter) {
	n.Selector = IPV6
	copy(n.union[:], (*[unsafe.Sizeof(filter)]byte)(unsafe.Pointer(&filter))[:])
}

// GetIPv4 gets the IPv4 filter from the NetworkLayerFilter
func (n *NetworkLayerFilter) GetIPv4() *IPv4Filter {
	if n.Selector != IPV4 {
		return nil
	}
	return (*IPv4Filter)(unsafe.Pointer(&n.union[0]))
}

// GetIPv6 gets the IPv6 filter from the NetworkLayerFilter
func (n *NetworkLayerFilter) GetIPv6() *IPv6Filter {
	if n.Selector != IPV6 {
		return nil
	}
	return (*IPv6Filter)(unsafe.Pointer(&n.union[0]))
}

const (
	TCPUDP = 0x00000001
	ICMP   = 0x00000002
)

// TransportLayerFilter represents transport layer filter level
type TransportLayerFilter struct {
	Selector uint32
	union    [unsafe.Sizeof(TCPUDPFilter{})]byte // To ensure the struct is packed exactly like the C++ union
}

// SetTCPUDP sets the TransportLayerFilter to a TCP/UDP filter
func (t *TransportLayerFilter) SetTCPUDP(filter TCPUDPFilter) {
	t.Selector = TCPUDP
	copy(t.union[:], (*[unsafe.Sizeof(filter)]byte)(unsafe.Pointer(&filter))[:])
}

// SetICMP sets the TransportLayerFilter to an ICMP filter
func (t *TransportLayerFilter) SetICMP(filter ICMPFilter) {
	t.Selector = ICMP
	copy(t.union[:], (*[unsafe.Sizeof(filter)]byte)(unsafe.Pointer(&filter))[:])
}

// GetTCPUDP gets the TCP/UDP filter from the TransportLayerFilter
func (t *TransportLayerFilter) GetTCPUDP() *TCPUDPFilter {
	if t.Selector != TCPUDP {
		return nil
	}
	return (*TCPUDPFilter)(unsafe.Pointer(&t.union[0]))
}

// GetICMP gets the ICMP filter from the TransportLayerFilter
func (t *TransportLayerFilter) GetICMP() *ICMPFilter {
	if t.Selector != ICMP {
		return nil
	}
	return (*ICMPFilter)(unsafe.Pointer(&t.union[0]))
}

const (
	FILTER_PACKET_PASS     = 0x00000001 // Pass packet if it matches the filter
	FILTER_PACKET_DROP     = 0x00000002 // Drop packet if it matches the filter
	FILTER_PACKET_REDIRECT = 0x00000003 // Redirect packet to WinpkFilter client application
	FILTER_PACKET_PASS_RDR = 0x00000004 // Redirect packet to WinpkFilter client application and pass over network (listen mode)
	FILTER_PACKET_DROP_RDR = 0x00000005 // Redirect packet to WinpkFilter client application and drop it, e.g. log but remove from the flow (listen mode)

	DATA_LINK_LAYER_VALID = 0x00000001 // Match packet against data link layer filter
	NETWORK_LAYER_VALID   = 0x00000002 // Match packet against network layer filter
	TRANSPORT_LAYER_VALID = 0x00000004 // Match packet against transport layer filter
)

// StaticFilter defines a static filter entry
type StaticFilter struct {
	Adapter        Handle
	DirectionFlags uint32
	FilterAction   uint32
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
type InitialStaticFilterTable struct {
	TableSize     uint32
	Padding       uint32
	StaticFilters [AnySize]StaticFilter
}

// StaticFilterTable represents a table of static filters
type StaticFilterTable struct {
	TableSize     uint32
	Padding       uint32
	StaticFilters []StaticFilter
}

// StaticFilterWithPosition represents a static filter with a specific insertion position.
type StaticFilterWithPosition struct {
	Position     uint32
	StaticFilters StaticFilter
}

// SetPacketFilterTable sets the static packet filter table for the Windows Packet Filter driver.
func (a *NdisApi) SetPacketFilterTable(packet *StaticFilterTable) error {
	var size uint32 = 0
	if packet != nil {
		size = uint32(unsafe.Sizeof(InitialStaticFilterTable{})) + (packet.TableSize-1)*uint32(unsafe.Sizeof(StaticFilter{}))
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

// AddStaticFilterFront adds a static filter to the front of the filter list in the Windows Packet Filter driver.
func (a *NdisApi) AddStaticFilterFront(filter *StaticFilter) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_ADD_PACKET_FILTER_FRONT,
		unsafe.Pointer(filter),
		uint32(unsafe.Sizeof(StaticFilter{})),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// AddStaticFilterBack adds a static filter to the end of the filter chain.
func (a *NdisApi) AddStaticFilterBack(filter *StaticFilter) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_ADD_PACKET_FILTER_BACK,
		unsafe.Pointer(filter),
		uint32(unsafe.Sizeof(StaticFilter{})),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// InsertStaticFilter inserts a static filter at a specified position in the filter chain.
func (a *NdisApi) InsertStaticFilter(filter *StaticFilter, position uint32) error {
	staticFilter := StaticFilterWithPosition{
		Position:     position,
		StaticFilters: *filter,
	}
	return a.DeviceIoControl(
		IOCTL_NDISRD_INSERT_FILTER_BY_INDEX,
		unsafe.Pointer(&staticFilter),
		uint32(unsafe.Sizeof(StaticFilterWithPosition{})),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// InsertStaticFilter removes a static filter by its unique identifier.
func (a *NdisApi) RemoveStaticFilter(filterID uint32) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_REMOVE_FILTER_BY_INDEX,
		unsafe.Pointer(&filterID),
		uint32(unsafe.Sizeof(filterID)),
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
func (a *NdisApi) GetPacketFilterTableSize() (uint32, error) {
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
		return 0, err
	}

	return tableSize, nil
}

// GetPacketFilterTable retrieves the static packet filter table from the Windows Packet Filter driver.
func (a *NdisApi) GetPacketFilterTable(tableSize uint32) (*StaticFilterTable, error) {
	// Allocate memory for the filter table
	var bufferSize int = int(unsafe.Sizeof(InitialStaticFilterTable{})) + (int(tableSize)-AnySize)*int(unsafe.Sizeof(StaticFilter{}))
	tableBuffer := make([]byte, bufferSize)

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS,
		nil,
		0,
		unsafe.Pointer(&tableBuffer[0]),
		uint32(bufferSize),
		&a.bytesReturned, // Bytes Returned
		nil,
	)
	if err != nil {
		return nil, err
	}

	filterList := &StaticFilterTable{
		TableSize:     tableSize,
		Padding:       0,
		StaticFilters: make([]StaticFilter, tableSize),
	}

	for i := 0; i < int(tableSize); i++ {
		offset := 8 + i*int(unsafe.Sizeof(StaticFilter{}))
		filterList.StaticFilters[i] = *(*StaticFilter)(unsafe.Pointer(&tableBuffer[offset]))
	}

	return filterList, nil
}

// GetPacketFilterTableResetStats retrieves the static packet filter table and resets statistics for the Windows Packet Filter driver.
func (a *NdisApi) GetPacketFilterTableResetStats() (*StaticFilterTable, error) {
	var staticFilterTable StaticFilterTable

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
		nil,
		0,
		unsafe.Pointer(&staticFilterTable),
		uint32(unsafe.Sizeof(StaticFilterTable{}))+(staticFilterTable.TableSize-AnySize)*uint32(unsafe.Sizeof(StaticFilter{})),
		nil, // Bytes Returned
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &staticFilterTable, nil
}

// SetPacketFilterCacheState sets the state of the packet filter cache.
func (a *NdisApi) SetPacketFilterCacheState(state bool) error {
	var cacheState uint32
	if state {
		cacheState = 1
	} else {
		cacheState = 0
	}
	return a.DeviceIoControl(
		IOCTL_NDISRD_SET_FILTER_CACHE_STATE,
		unsafe.Pointer(&cacheState),
		uint32(unsafe.Sizeof(cacheState)),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// SetPacketFragmentCacheState sets the state of the packet fragment cache.
func (a *NdisApi) SetPacketFragmentCacheState(state bool) error {
	var cacheState uint32
	if state {
		cacheState = 1
	} else {
		cacheState = 0
	}
	return a.DeviceIoControl(
		IOCTL_NDISRD_SET_FRAGMENT_CACHE_STATE,
		unsafe.Pointer(&cacheState),
		uint32(unsafe.Sizeof(cacheState)),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// EnablePacketFilterCache enables the packet filter cache.
func (a *NdisApi) EnablePacketFilterCache() error {
	return a.SetPacketFilterCacheState(true)
}

// DisablePacketFilterCache disables the packet filter cache.
func (a *NdisApi) DisablePacketFilterCache() error {
	return a.SetPacketFilterCacheState(false)
}

// EnablePacketFragmentCache enables the packet fragment cache.
func (a *NdisApi) EnablePacketFragmentCache() error {
	return a.SetPacketFragmentCacheState(true)
}

// DisablePacketFragmentCache disables the packet fragment cache.
func (a *NdisApi) DisablePacketFragmentCache() error {
	return a.SetPacketFragmentCacheState(false)
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
