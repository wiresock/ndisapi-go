//go:build windows

package ndisapi

import (
	"unsafe"
)

const UnsortedMaximumBlockNum = 16
const UnsortedMaximumPacketBlock = 512
const FastIOMaximumPacketBlock = 2048 * 3

// FastIOWriteUnion defines the union type for fast I/O write.
type FastIOWriteUnion struct {
	union uint32
}

// Split returns the split field of a union type containing respectively NumberOfPackets and WriteInProgressFlag.
func (h *FastIOWriteUnion) GetNumberOfPackets() uint16 {
	return uint16(h.union & 0xFFFF)
}

func (h *FastIOWriteUnion) GetWriteInProgressFlag() uint16 {
	return uint16((h.union >> 16) & 0xFFFF)
}

func (h *FastIOWriteUnion) SetNumberOfPackets(value uint16) {
	h.union = (h.union & 0xFFFF0000) | uint32(value)
}

func (h *FastIOWriteUnion) SetWriteInProgressFlag(value uint16) {
	h.union = (h.union & 0x0000FFFF) | (uint32(value) << 16)
}

// Join combines the NumberOfPackets and WriteInProgressFlag into a single uint32 value.
func (h *FastIOWriteUnion) GetJoin() *uint32 {
	return &h.union
}

// SetJoin sets the FastIOWriteUnion fields from a single uint32 value.
func (h *FastIOWriteUnion) SetJoin(join uint32) {
	h.union = join
}

// FastIOSectionHeader defines the header for a fast I/O section.
type FastIOSectionHeader struct {
	FastIOWriteUnion   FastIOWriteUnion
	ReadInProgressFlag uint32
}

// FastIOSection represents a section containing intermediate buffers for fast I/O.
type InitializeFastIOSection struct {
	FastIOHeader  FastIOSectionHeader
	FastIOPackets [AnySize]IntermediateBuffer // Assumes IntermediateBuffer is defined elsewhere
}
type FastIOSection struct {
	FastIOHeader  FastIOSectionHeader
	FastIOPackets [FastIOMaximumPacketBlock]IntermediateBuffer // Assumes IntermediateBuffer is defined elsewhere
}

// InitializeFastIOParams defines parameters for initializing a fast I/O section.
type InitializeFastIOParams struct {
	Header   *InitializeFastIOSection
	DataSize uint32
}

// UnsortedReadSendRequest represents a request for unsorted read/send packets
type UnsortedReadSendRequest struct {
	Packets    []*IntermediateBuffer
	PacketsNum uint32
}

// InitializeFastIo initializes the Fast I/O shared memory section.
func (a *NdisApi) InitializeFastIo(fastIo *InitializeFastIOSection, size uint32) bool {
	if size < uint32(unsafe.Sizeof(InitializeFastIOSection{})) {
		return false
	}

	params := InitializeFastIOParams{Header: fastIo, DataSize: size}

	err := a.DeviceIoControl(
		IOCTL_NDISRD_INITIALIZE_FAST_IO,
		unsafe.Pointer(&params),
		uint32(unsafe.Sizeof(params)),
		nil,
		0,
		&a.bytesReturned,
		nil,
	)

	return err == nil
}

// AddSecondaryFastIo adds a secondary Fast I/O shared memory section.
func (a *NdisApi) AddSecondaryFastIo(fastIo *InitializeFastIOSection, size uint32) bool {
	if size < uint32(unsafe.Sizeof(InitializeFastIOSection{})) {
		return false
	}

	params := InitializeFastIOParams{Header: fastIo, DataSize: size}

	err := a.DeviceIoControl(
		IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION,
		unsafe.Pointer(&params),
		uint32(unsafe.Sizeof(params)),
		nil,
		0,
		&a.bytesReturned,
		nil,
	)

	return err == nil
}

// ReadPacketsUnsorted reads a bunch of packets from the driver packet queues without sorting by network adapter.
func (a *NdisApi) ReadPacketsUnsorted(packets []*IntermediateBuffer, packetsNum uint32, packetsSuccess *uint32) bool {
	request := UnsortedReadSendRequest{
		Packets:    make([]*IntermediateBuffer, packetsNum),
		PacketsNum: packetsNum,
	}
	copy(request.Packets, packets[:packetsNum])

	err := a.DeviceIoControl(
		IOCTL_NDISRD_READ_PACKETS_UNSORTED,
		unsafe.Pointer(&request),
		uint32(unsafe.Sizeof(request)),
		unsafe.Pointer(&request),
		uint32(unsafe.Sizeof(request)),
		&a.bytesReturned,
		nil,
	)

	len := uint32(len(request.Packets))
	copy(packets[0:len], request.Packets[0:len])

	*packetsSuccess = len

	return err == nil
}

// SendPacketsToAdaptersUnsorted sends a bunch of packets to the network adapters.
func (a *NdisApi) SendPacketsToAdaptersUnsorted(packets []*IntermediateBuffer, packetsNum uint32, packetSuccess *uint32) bool {
	request := UnsortedReadSendRequest{
		Packets:    make([]*IntermediateBuffer, packetsNum),
		PacketsNum: packetsNum,
	}
	copy(request.Packets, packets[:packetsNum])

	err := a.DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED,
		unsafe.Pointer(&request),
		uint32(unsafe.Sizeof(request)),
		unsafe.Pointer(&request),
		uint32(unsafe.Sizeof(request)),
		&a.bytesReturned,
		nil,
	)

	*packetSuccess = request.PacketsNum

	return err == nil
}

// SendPacketsToMstcpUnsorted indicates a bunch of packets to the MSTCP (and other upper layer network protocols).
func (a *NdisApi) SendPacketsToMstcpUnsorted(packets []*IntermediateBuffer, packetsNum uint32, packetSuccess *uint32) bool {
	request := UnsortedReadSendRequest{
		Packets:    make([]*IntermediateBuffer, packetsNum),
		PacketsNum: packetsNum,
	}
	copy(request.Packets, packets[:packetsNum])

	err := a.DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED,
		unsafe.Pointer(&request),
		uint32(unsafe.Sizeof(request)),
		unsafe.Pointer(&request),
		uint32(unsafe.Sizeof(request)),
		&a.bytesReturned,
		nil,
	)

	*packetSuccess = request.PacketsNum

	return err == nil
}
