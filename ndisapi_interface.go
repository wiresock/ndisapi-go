//go:build windows

package ndisapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// NdisApiInterface defines the interface for NDISAPI driver interactions.
type NdisApiInterface interface {
	DeviceIoControl(service uint32, in unsafe.Pointer, sizeIn uint32, out unsafe.Pointer, sizeOut uint32, SizeRet *uint32, overlapped *windows.Overlapped) error
	IsDriverLoaded() bool
	Close()
	GetVersion() (uint32, error)
	GetIntermediateBufferPoolSize(size uint32) error
	NdisApiAdapter
	NdisApiFastIO
	NdisApiIO
	NdisApiStaticFilters
	IsNdiswanInterfaces(adapterName, ndiswanName string) bool
	IsNdiswanIP(adapterName string) bool
	IsNdiswanIPv6(adapterName string) bool
	IsNdiswanBh(adapterName string) bool
	IsWindows10OrGreater() bool
}

type NdisApiAdapter interface {
	GetTcpipBoundAdaptersInfo() (*TcpAdapterList, error)
	SetAdapterMode(currentMode *AdapterMode) error
	GetAdapterMode(currentMode *AdapterMode) error
	FlushAdapterPacketQueue(adapter Handle) error
	GetAdapterPacketQueueSize(adapter Handle, size *uint32) error
	SetPacketEvent(adapter Handle, win32Event windows.Handle) error
	SetAdapterListChangeEvent(win32Event windows.Handle) error
	ConvertWindows2000AdapterName(adapterName string) string
}

type NdisApiFastIO interface {
	InitializeFastIo(pFastIo *InitializeFastIOSection, dwSize uint32) bool
	AddSecondaryFastIo(fastIo *InitializeFastIOSection, size uint32) bool
	ReadPacketsUnsorted(packets []*IntermediateBuffer, packetsNum uint32, packetsSuccess *uint32) bool
	SendPacketsToAdaptersUnsorted(packets []*IntermediateBuffer, packetsNum uint32, packetSuccess *uint32) bool
	SendPacketsToMstcpUnsorted(packets []*IntermediateBuffer, packetsNum uint32, packetSuccess *uint32) bool
}

type NdisApiIO interface {
	SendPacketToMstcp(packet *EtherRequest) error
	SendPacketToAdapter(packet *EtherRequest) error
	ReadPacket(packet *EtherRequest) bool
	SendPacketsToMstcp(packet *EtherMultiRequest) error
	SendPacketsToAdapter(packet *EtherMultiRequest) error
	ReadPackets(packet *EtherMultiRequest) bool
}

type NdisApiStaticFilters interface {
	SetPacketFilterTable(packet *StaticFilterTable) error
	AddStaticFilterFront(filter *StaticFilter) error
	AddStaticFilterBack(filter *StaticFilter) error
	InsertStaticFilter(filter *StaticFilter, position uint32) error
	RemoveStaticFilter(filterID uint32) error
	ResetPacketFilterTable() error
	GetPacketFilterTableSize() (uint32, error)
	GetPacketFilterTable(uint32) (*StaticFilterTable, error)
	GetPacketFilterTableResetStats() (*StaticFilterTable, error)
	SetPacketFilterCacheState(state bool) error
	SetPacketFragmentCacheState(state bool) error
	EnablePacketFilterCache() error
	DisablePacketFilterCache() error
	EnablePacketFragmentCache() error
	DisablePacketFragmentCache() error
}