//go:build windows

package ndisapi

import (
	"encoding/binary"
	"unsafe"
)

// common constants
const (
	NDISRD_VERSION       = 0x06013000
	NDISRD_MAJOR_VERSION = 0x0003
	NDISRD_MINOR_VERSION = 0x0601

	// Common strings set
	DRIVER_NAME     = "NDISRD"
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

	AnySize = 1
)

// Packet actions
type FilterAction uint32

const (
	FilterActionPass FilterAction = iota
	FilterActionDrop
	FilterActionRedirect
	FilterActionPassRedirect
	FilterActionDropRedirect
)

// Handle is equivalent to HANDLE to store windows native handle
// using windows.Handle will not help as its type is uintptr which we don't want that
type Handle [8]byte

type QLink [16]byte

// HAdapterQLinkUnion represents the interface for union-type values in IntermediateBuffer.
type HAdapterQLinkUnion struct {
	data [16]byte
}

// GetAdapter returns the adapter handle from the HAdapterQLinkUnion.
func (h *HAdapterQLinkUnion) GetAdapter() Handle {
	return *(*Handle)(unsafe.Pointer(&h.data[0]))
}

// GetQLink returns the 16 bytes of QLink from the HAdapterQLinkUnion.
func (h *HAdapterQLinkUnion) GetQLink() QLink {
	return *(*QLink)(unsafe.Pointer(&h.data[0]))
}

// IntermediateBuffer contains packet buffer, packet NDIS flags, WinpkFilter specific flags
type IntermediateBuffer struct {
	HAdapterQLinkUnion HAdapterQLinkUnion
	DeviceFlags        uint32
	Length             uint32
	Flags              uint32 // NDIS_PACKET flags
	M8021q             uint32 // 802.1q tag
	FilterID           uint32
	Reserved           [4]uint32
	Buffer             [MAX_ETHER_FRAME]byte
}

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
