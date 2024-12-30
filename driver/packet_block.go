//go:build windows

package driver

import (
	"unsafe"

	A "github.com/wiresock/ndisapi-go"
)

// RequestStorageType represents the storage type for requests.
type RequestStorageType [unsafe.Sizeof(A.EtherMultiRequest{}) + unsafe.Sizeof(A.EthernetPacket{})*(A.MaximumPacketBlock-1)]byte

// PacketBlock represents a block of packets.
type PacketBlock struct {
	packetBuffer        *[A.MaximumPacketBlock]A.IntermediateBuffer
	readRequest         *RequestStorageType
	writeAdapterRequest *RequestStorageType
	writeMstcpRequest   *RequestStorageType
}

// NewPacketBlock creates a new PacketBlock.
func NewPacketBlock(adapter A.Handle) *PacketBlock {
	packetBlock := &PacketBlock{
		packetBuffer: &[A.MaximumPacketBlock]A.IntermediateBuffer{},
		readRequest:         &RequestStorageType{},
		writeAdapterRequest: &RequestStorageType{},
		writeMstcpRequest:   &RequestStorageType{},
	}

	readRequest := (*A.EtherMultiRequest)(unsafe.Pointer(packetBlock.readRequest))
	writeAdapterRequest := (*A.EtherMultiRequest)(unsafe.Pointer(packetBlock.writeAdapterRequest))
	writeMstcpRequest := (*A.EtherMultiRequest)(unsafe.Pointer(packetBlock.writeMstcpRequest))

	readRequest.AdapterHandle = adapter
	writeAdapterRequest.AdapterHandle = adapter
	writeMstcpRequest.AdapterHandle = adapter

	readRequest.PacketsNumber = A.MaximumPacketBlock
	readRequest.EthernetPackets = [A.MaximumPacketBlock]A.EthernetPacket{}

	for i := 0; i < A.MaximumPacketBlock; i++ {
		readRequest.EthernetPackets[i].Buffer = &packetBlock.packetBuffer[i]
	}

	return packetBlock
}

// GetReadRequest returns the read request.
func (p *PacketBlock) GetReadRequest() *A.EtherMultiRequest {
	return (*A.EtherMultiRequest)(unsafe.Pointer(p.readRequest))
}

// GetWriteAdapterRequest returns the write adapter request.
func (p *PacketBlock) GetWriteAdapterRequest() *A.EtherMultiRequest {
	return (*A.EtherMultiRequest)(unsafe.Pointer(p.writeAdapterRequest))
}

// GetWriteMstcpRequest returns the write MSTCP request.
func (p *PacketBlock) GetWriteMstcpRequest() *A.EtherMultiRequest {
	return (*A.EtherMultiRequest)(unsafe.Pointer(p.writeMstcpRequest))
}
