//go:build windows

package ndisapi

import (
	"unsafe"
)

const MaximumBlockNum = 10
const MaximumPacketBlock = 510

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

// SendPacketToMstcp sends a packet to the MSTCP.
func (a *NdisApi) SendPacketToMstcp(packet *EtherRequest) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
		unsafe.Pointer(packet),
		uint32(unsafe.Sizeof(EtherRequest{})),
		nil,
		0,
		&a.bytesReturned,
		nil,
	)
}

// SendPacketToAdapter sends a packet to the network adapter.
func (a *NdisApi) SendPacketToAdapter(packet *EtherRequest) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
		unsafe.Pointer(packet),
		uint32(unsafe.Sizeof(EtherRequest{})),
		nil,
		0,
		&a.bytesReturned,
		nil,
	)
}

// ReadPacket reads a packet from the Windows Packet Filter driver.
func (a *NdisApi) ReadPacket(packet *EtherRequest) bool {
	size := uint32(unsafe.Sizeof(EtherRequest{}))
	err := a.DeviceIoControl(
		IOCTL_NDISRD_READ_PACKET,
		unsafe.Pointer(packet),
		size,
		unsafe.Pointer(packet),
		size,
		nil,
		nil,
	)

	return err != nil
}

// SendPacketsToMstcp sends multiple packets to the Microsoft TCP/IP stack.
func (a *NdisApi) SendPacketsToMstcp(packet *EtherMultiRequest) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
		unsafe.Pointer(packet),
		uint32(unsafe.Sizeof(EtherMultiRequest{}))+uint32(unsafe.Sizeof(EthernetPacket{}))*(packet.PacketsNumber-1),
		nil,
		0,
		&a.bytesReturned,
		nil,
	)
}

// SendPacketsToAdapter sends multiple packets to the network adapter.
func (a *NdisApi) SendPacketsToAdapter(packet *EtherMultiRequest) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
		unsafe.Pointer(packet),
		uint32(unsafe.Sizeof(EtherMultiRequest{}))+uint32(unsafe.Sizeof(EthernetPacket{}))*(packet.PacketsNumber-1),
		nil,
		0,
		&a.bytesReturned,
		nil,
	)
}

// ReadPackets reads multiple packets from the network adapter.
func (a *NdisApi) ReadPackets(packet *EtherMultiRequest) bool {
	size := uint32(unsafe.Sizeof(EtherMultiRequest{})) + uint32(unsafe.Sizeof(EthernetPacket{}))*(packet.PacketsNumber-1)
	err := a.DeviceIoControl(
		IOCTL_NDISRD_READ_PACKETS,
		unsafe.Pointer(packet),
		size,
		unsafe.Pointer(packet),
		size,
		&a.bytesReturned,
		nil,
	)

	return err != nil
}
