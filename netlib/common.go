//go:build windows

package netlib

const (
	FILTER_PACKET_PASS     = 0x00000001 // Pass packet if it matches the filter
	FILTER_PACKET_DROP     = 0x00000002 // Drop packet if it matches the filter
	FILTER_PACKET_REDIRECT = 0x00000003 // Redirect packet to WinpkFilter client application
	FILTER_PACKET_PASS_RDR = 0x00000004 // Redirect packet to WinpkFilter client application and pass over network (listen mode)
	FILTER_PACKET_DROP_RDR = 0x00000005 // Redirect packet to WinpkFilter client application and drop it, e.g. log but remove from the flow (listen mode)

	DATA_LINK_LAYER_VALID = 0x00000001 // Match packet against data link layer filter
	NETWORK_LAYER_VALID   = 0x00000002 // Match packet against network layer filter
	TRANSPORT_LAYER_VALID = 0x00000004 // Match packet against transport layer filter

	TCPUDP = 0x00000001
	ICMP   = 0x00000002

	IPV4 = 0x00000001
	IPV6 = 0x00000002

	ICMP_TYPE = 0x00000001
	ICMP_CODE = 0x00000002

	ETH_802_3 = 0x00000001

	ETH_802_3_SRC_ADDRESS  = 0x00000001
	ETH_802_3_DEST_ADDRESS = 0x00000002
	ETH_802_3_PROTOCOL     = 0x00000004

	IP_V4_FILTER_SRC_ADDRESS  = 0x00000001
	IP_V4_FILTER_DEST_ADDRESS = 0x00000002
	IP_V4_FILTER_PROTOCOL     = 0x00000004

	IP_V6_FILTER_SRC_ADDRESS  = 0x00000001
	IP_V6_FILTER_DEST_ADDRESS = 0x00000002
	IP_V6_FILTER_PROTOCOL     = 0x00000004

	TCPUDP_SRC_PORT  = 0x00000001
	TCPUDP_DEST_PORT = 0x00000002
	TCPUDP_TCP_FLAGS = 0x00000004

	TH_FIN = 0x01
	TH_SYN = 0x02
	TH_RST = 0x04
	TH_PSH = 0x08
	TH_ACK = 0x10
	TH_URG = 0x20
)

const ANY_SIZE = 1

type TCP_CONNECTION_OFFLOAD_STATE int32

const (
	TcpConnectionOffloadStateInHost TCP_CONNECTION_OFFLOAD_STATE = iota
	TcpConnectionOffloadStateOffloading
	TcpConnectionOffloadStateOffloaded
	TcpConnectionOffloadStateUploading
	TcpConnectionOffloadStateMax
)

const TCPIP_OWNING_MODULE_SIZE = 16

type MIB_TCPROW_OWNER_MODULE struct {
	DwState           uint32
	DwLocalAddr       uint32
	DwLocalPort       uint32
	DwRemoteAddr      uint32
	DwRemotePort      uint32
	DwOwningPid       uint32
	LiCreateTimestamp uint64
	OwningModuleInfo  [TCPIP_OWNING_MODULE_SIZE]uint64
}
type PMIB_TCPROW_OWNER_MODULE *MIB_TCPROW_OWNER_MODULE

type MIB_TCPTABLE_OWNER_MODULE struct {
	DwNumEntries uint32
	Table        [ANY_SIZE]MIB_TCPROW_OWNER_MODULE
}
type PMIB_TCPTABLE_OWNER_MODULE *MIB_TCPTABLE_OWNER_MODULE


type TCP_TABLE_CLASS int32

const (
	TCP_TABLE_BASIC_LISTENER TCP_TABLE_CLASS = iota
	TCP_TABLE_BASIC_CONNECTIONS
	TCP_TABLE_BASIC_ALL
	TCP_TABLE_OWNER_PID_LISTENER
	TCP_TABLE_OWNER_PID_CONNECTIONS
	TCP_TABLE_OWNER_PID_ALL
	TCP_TABLE_OWNER_MODULE_LISTENER
	TCP_TABLE_OWNER_MODULE_CONNECTIONS
	TCP_TABLE_OWNER_MODULE_ALL
)

type TCPIP_OWNER_MODULE_INFO_CLASS int32

const (
	TCPIP_OWNER_MODULE_INFO_BASIC TCPIP_OWNER_MODULE_INFO_CLASS = iota
)

type TCPIP_OWNER_MODULE_BASIC_INFO struct {
	ModuleName *uint16
	ModulePath *uint16
}
