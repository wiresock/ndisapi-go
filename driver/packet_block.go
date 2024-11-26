//go:build windows

package driver

import (
	"unsafe"

	A "github.com/amir-devman/ndisapi-go"
)

type RequestStorageType [unsafe.Sizeof(A.EtherMultiRequest{}) + unsafe.Sizeof(A.EthernetPacket{})*(A.MaximumPacketBlock-1)]byte

type PacketBlock struct {
	packetBuffer        [A.MaximumPacketBlock]A.IntermediateBuffer
	readRequest         *RequestStorageType
	writeAdapterRequest *RequestStorageType
	writeMstcpRequest   *RequestStorageType
}

func NewPacketBlock(adapter A.Handle) *PacketBlock {
	packetBlock := &PacketBlock{
		packetBuffer: [A.MaximumPacketBlock]A.IntermediateBuffer{},

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

func (p *PacketBlock) GetReadRequest() *A.EtherMultiRequest {
	return (*A.EtherMultiRequest)(unsafe.Pointer(p.readRequest))
}

func (p *PacketBlock) GetWriteAdapterRequest() *A.EtherMultiRequest {
	return (*A.EtherMultiRequest)(unsafe.Pointer(p.writeAdapterRequest))
}

func (p *PacketBlock) GetWriteMstcpRequest() *A.EtherMultiRequest {
	return (*A.EtherMultiRequest)(unsafe.Pointer(p.writeMstcpRequest))
}
