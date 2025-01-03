//go:build windows

package ndisapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
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
		nil, // Bytes Returned
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
		nil, // Bytes Returned
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
		nil, // Bytes Returned
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
		nil, // Bytes Returned
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
		nil,
		nil,
	)

	return err != nil
}

// FlushAdapterPacketQueue flushes the packet queue of the specified network adapter.
func (a *NdisApi) FlushAdapterPacketQueue(handle Handle) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
		unsafe.Pointer(&handle),
		uint32(len(handle)),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

// SetPacketEvent sets a Win32 event to be signaled when a packet arrives at the specified network adapter.
func (a *NdisApi) SetPacketEvent(adapter Handle, win32Event windows.Handle) error {
	adapterEvent := AdapterEvent{
		AdapterHandle: adapter,
		Event:         win32Event,
	}

	return a.DeviceIoControl(
		IOCTL_NDISRD_SET_EVENT,
		unsafe.Pointer(&adapterEvent),
		uint32(unsafe.Sizeof(adapterEvent)),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}
