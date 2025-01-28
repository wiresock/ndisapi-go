//go:build windows

package driver

import (
	A "github.com/wiresock/ndisapi-go"
)

// UnsortedPacketBlock represents a block of unsorted packets.
type UnsortedPacketBlock struct {
	packetsSuccess      uint32
	packetBuffer        []A.IntermediateBuffer
	readRequest         []*A.IntermediateBuffer
	writeAdapterRequest []*A.IntermediateBuffer
	writeMstcpRequest   []*A.IntermediateBuffer
}

// NewUnsortedPacketBlock creates a new UnsortedPacketBlock.
func NewUnsortedPacketBlock() *UnsortedPacketBlock {
	block := &UnsortedPacketBlock{
		packetBuffer:        make([]A.IntermediateBuffer, A.UnsortedMaximumPacketBlock),
		readRequest:         make([]*A.IntermediateBuffer, A.UnsortedMaximumPacketBlock),
		writeAdapterRequest: make([]*A.IntermediateBuffer, 0, A.UnsortedMaximumPacketBlock),
		writeMstcpRequest:   make([]*A.IntermediateBuffer, 0, A.UnsortedMaximumPacketBlock),
	}

	for i := 0; i < A.UnsortedMaximumPacketBlock; i++ {
		block.readRequest[i] = &block.packetBuffer[i]
	}

	return block
}

// GetReadRequest returns the read request.
func (b *UnsortedPacketBlock) GetReadRequest() []*A.IntermediateBuffer {
	return b.readRequest
}

// GetWriteAdapterRequest returns the write adapter request.
func (b *UnsortedPacketBlock) GetWriteAdapterRequest() []*A.IntermediateBuffer {
	return b.writeAdapterRequest
}

// GetWriteMstcpRequest returns the write MSTCP request.
func (b *UnsortedPacketBlock) GetWriteMstcpRequest() []*A.IntermediateBuffer {
	return b.writeMstcpRequest
}

// GetPacketBuffer returns the packet buffer.
func (b *UnsortedPacketBlock) GetPacketBuffer() []A.IntermediateBuffer {
	return b.packetBuffer
}

// GetPacketsSuccess returns the number of successfully read packets.
func (b *UnsortedPacketBlock) GetPacketsSuccess() uint32 {
	return b.packetsSuccess
}

// SetWriteAdapterRequest sets the write adapter request.
func (b *UnsortedPacketBlock) SetWriteAdapterRequest(request []*A.IntermediateBuffer) {
	b.writeAdapterRequest = request
}

// SetWriteMstcpRequest sets the write MSTCP request.
func (b *UnsortedPacketBlock) SetWriteMstcpRequest(request []*A.IntermediateBuffer) {
	b.writeMstcpRequest = request
}

// SetPacketsSuccess sets the number of successfully read packets.
func (b *UnsortedPacketBlock) SetPacketsSuccess(success uint32) {
	b.packetsSuccess = success
}

// ClearWriteAdapterRequest returns the write adapter request.
func (b *UnsortedPacketBlock) ClearWriteAdapterRequest() {
	b.writeAdapterRequest = make([]*A.IntermediateBuffer, 0, A.UnsortedMaximumPacketBlock)
}

// ClearWriteMstcpRequest returns the write MSTCP request.
func (b *UnsortedPacketBlock) ClearWriteMstcpRequest() {
	b.writeMstcpRequest = make([]*A.IntermediateBuffer, 0, A.UnsortedMaximumPacketBlock)
}
