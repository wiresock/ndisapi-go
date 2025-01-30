//go:build windows

package driver

import (
	A "github.com/wiresock/ndisapi-go"
)

// UnsortedPacketBlock represents a block of unsorted packets.
type UnsortedPacketBlock struct {
	PacketsSuccess      uint32
	PacketBuffer        []A.IntermediateBuffer
	ReadRequest         []*A.IntermediateBuffer
	WriteAdapterRequest []*A.IntermediateBuffer
	WriteMstcpRequest   []*A.IntermediateBuffer
}

// NewUnsortedPacketBlock creates a new UnsortedPacketBlock.
func NewUnsortedPacketBlock() *UnsortedPacketBlock {
	block := &UnsortedPacketBlock{
		PacketBuffer:        make([]A.IntermediateBuffer, A.UnsortedMaximumPacketBlock),
		ReadRequest:         make([]*A.IntermediateBuffer, A.UnsortedMaximumPacketBlock),
		WriteAdapterRequest: make([]*A.IntermediateBuffer, 0, A.UnsortedMaximumPacketBlock),
		WriteMstcpRequest:   make([]*A.IntermediateBuffer, 0, A.UnsortedMaximumPacketBlock),
	}

	for i := 0; i < A.UnsortedMaximumPacketBlock; i++ {
		block.ReadRequest[i] = &block.PacketBuffer[i]
	}

	return block
}
