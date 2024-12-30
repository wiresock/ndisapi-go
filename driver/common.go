//go:build windows

package driver

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
)
