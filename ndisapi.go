//go:build windows

package ndisapi

import (
	"bytes"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	DEVICE_NDISWANIP               = `\\DEVICE\\NDISWANIP`
	USER_NDISWANIP                 = `WAN Network Interface (IP)`
	DEVICE_NDISWANBH               = `\\DEVICE\\NDISWANBH`
	USER_NDISWANBH                 = `WAN Network Interface (BH)`
	DEVICE_NDISWANIPV6             = `\\DEVICE\\NDISWANIPV6`
	USER_NDISWANIPV6               = `WAN Network Interface (IPv6)`
	REGSTR_COMPONENTID_NDISWANIP   = `ms_ndiswanip`
	REGSTR_COMPONENTID_NDISWANIPV6 = `ms_ndiswanipv6`
	REGSTR_COMPONENTID_NDISWANBH   = `ms_ndiswanbh`
	REGSTR_VAL_CONNECTION          = `\Connection`
	REGSTR_VAL_NAME                = `Name`
	REGSTR_VAL_SERVICE_NAME        = `ServiceName`
	REGSTR_VAL_DRIVER_DESC         = `DriverDesc`
	REGSTR_VAL_TITLE               = `Title`

	REGSTR_NETWORK_CONTROL_KEY   = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\`
	REGSTR_NETWORK_CARDS         = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards`
	REGSTR_MSTCP_CLASS_NET       = `SYSTEM\CurrentControlSet\Services\Class\Net\`
	REGSTR_NETWORK_CONTROL_CLASS = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`

	OID_GEN_CURRENT_PACKET_FILTER = 0x0001010E
)

type NdisApi struct {
	overlapped    windows.Overlapped
	bytesReturned uint32

	fileHandle           windows.Handle
	isLoadedSuccessfully bool
}

func NewNdisApi() (*NdisApi, error) {
	devicePath, err := windows.UTF16PtrFromString("\\\\.\\NDISRD")
	if err != nil {
		return nil, err
	}

	overlapped := windows.Overlapped{}

	isLoadSuccessfully := false

	fileHandle, err := windows.CreateFile(
		devicePath, // Device path
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err == windows.ERROR_INVALID_HANDLE {
		overlapped.HEvent = 0
	} else {
		overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			isLoadSuccessfully = true
		}
	}

	ndisApi := &NdisApi{
		overlapped:    overlapped,
		bytesReturned: 0,

		fileHandle:           fileHandle,
		isLoadedSuccessfully: isLoadSuccessfully,
	}

	return ndisApi, nil
}

func (a *NdisApi) Close() {
	if a.fileHandle != windows.InvalidHandle {
		windows.CloseHandle(a.fileHandle)
	}

	if a.overlapped.HEvent != 0 {
		windows.CloseHandle(a.overlapped.HEvent)
	}
}

func (a *NdisApi) IsDriverLoaded() bool {
	return a.isLoadedSuccessfully
}

func (a *NdisApi) DeviceIoControl(service uint32, in unsafe.Pointer, sizeIn uint32, out unsafe.Pointer, sizeOut uint32, SizeRet *uint32, overlapped *windows.Overlapped) error {
	var returnedBytes uint32
	if SizeRet == nil {
		SizeRet = &returnedBytes
	}

	return windows.DeviceIoControl(
		a.fileHandle,
		service,
		(*byte)(in),
		sizeIn,
		(*byte)(out),
		sizeOut,
		SizeRet,
		overlapped)
}

func (a *NdisApi) GetTcpipBoundAdaptersInfo() (*TcpAdapterList, error) {
	var tcpAdapterList TcpAdapterList

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_TCPIP_INTERFACES,
		unsafe.Pointer(&tcpAdapterList),
		uint32(unsafe.Sizeof(tcpAdapterList)),
		unsafe.Pointer(&tcpAdapterList),
		uint32(unsafe.Sizeof(tcpAdapterList)),
		nil,
		nil,
	)

	if err != nil {
		return nil, err
	}

	return &tcpAdapterList, nil
}

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

func (a *NdisApi) SetAdapterMode(currentMode *AdapterMode) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_SET_ADAPTER_MODE,
		unsafe.Pointer(currentMode),
		uint32(unsafe.Sizeof(AdapterMode{})),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

func (a *NdisApi) GetAdapterMode(currentMode *AdapterMode) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_SET_ADAPTER_MODE,
		unsafe.Pointer(currentMode),
		uint32(unsafe.Sizeof(AdapterMode{})),
		unsafe.Pointer(currentMode),
		uint32(unsafe.Sizeof(AdapterMode{})),
		nil, // Bytes Returned
		nil,
	)
}

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

func (a *NdisApi) SetPacketFilterTable(packet *StaticFilterTable) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_SET_PACKET_FILTERS,
		unsafe.Pointer(packet),
		uint32(unsafe.Sizeof(StaticFilterTable{}))+(packet.TableSize-1)*uint32(unsafe.Sizeof(StaticFilterEntry{})),
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

func (a *NdisApi) ResetPacketFilterTable() error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_RESET_PACKET_FILTERS,
		nil,
		0,
		nil,
		0,
		nil, // Bytes Returned
		nil,
	)
}

func (a *NdisApi) GetPacketFilterTableSize() (*uint32, error) {
	var tableSize uint32

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE,
		nil,
		0,
		unsafe.Pointer(&tableSize),
		uint32(unsafe.Sizeof(tableSize)),
		nil,
		nil,
	)

	if err != nil {
		return nil, err
	}

	return &tableSize, nil
}

func (a *NdisApi) GetPacketFilterTable() (*StaticFilterTable, error) {
	var staticFilterTable StaticFilterTable

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS,
		nil,
		0,
		unsafe.Pointer(&staticFilterTable),
		uint32(unsafe.Sizeof(StaticFilterTable{}))+(staticFilterTable.TableSize-1)*uint32(unsafe.Sizeof(StaticFilterEntry{})),
		nil, // Bytes Returned
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &staticFilterTable, nil
}

func (a *NdisApi) GetPacketFilterTableResetStats() (*StaticFilterTable, error) {
	var staticFilterTable StaticFilterTable

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
		nil,
		0,
		unsafe.Pointer(&staticFilterTable),
		uint32(unsafe.Sizeof(StaticFilterTable{}))+(staticFilterTable.TableSize-1)*uint32(unsafe.Sizeof(StaticFilterEntry{})),
		nil, // Bytes Returned
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &staticFilterTable, nil
}

func (a *NdisApi) ConvertWindows2000AdapterName(adapterName string) string {
	if a.IsNdiswanIP(adapterName) {
		return USER_NDISWANIP
	}
	if a.IsNdiswanBh(adapterName) {
		return USER_NDISWANBH
	}
	if a.IsNdiswanIPv6(adapterName) {
		return USER_NDISWANIPV6
	}

	adapterNameBytes := []byte((strings.TrimPrefix(adapterName, `\DEVICE\`)))
	adapterNameBytes = bytes.Trim(adapterNameBytes, "\x00")

	keyPath := REGSTR_NETWORK_CONTROL_KEY + string(adapterNameBytes) + REGSTR_VAL_CONNECTION

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		return string(adapterNameBytes)
	}
	defer key.Close()

	val, _, err := key.GetStringValue(REGSTR_VAL_NAME)
	if err != nil {
		return string(adapterNameBytes)
	}

	return val
}

// RecalculateIPChecksum recalculates the IP checksum for the given packet.
func RecalculateIPChecksum(packet *IntermediateBuffer) {
	etherHeaderSize := int(unsafe.Sizeof(EtherHeader{}))
	if len(packet.Buffer) < etherHeaderSize {
		return
	}

	ipHeaderOffset := etherHeaderSize
	ipHeader := (*IPHeader)(unsafe.Pointer(&packet.Buffer[ipHeaderOffset])) // IP header pointer

	ipHeader.Checksum = 0
	sum := 0

	for i := 0; i < int(ipHeader.HeaderLength())*4; i += 2 {
		word16 := (uint16(packet.Buffer[ipHeaderOffset+i]) << 8) + uint16(packet.Buffer[ipHeaderOffset+i+1])
		sum += int(word16)
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	sum = ^sum

	ipHeader.Checksum = Htons(uint16(sum))
}

func RecalculateICMPChecksum(packet *IntermediateBuffer) {
	panic("not implmented yet")
}

// RecalculateTCPChecksum recalculates the TCP checksum for the given packet.
func RecalculateTCPChecksum(packet *IntermediateBuffer) {
	etherHeaderSize := int(unsafe.Sizeof(EtherHeader{}))
	if len(packet.Buffer) < etherHeaderSize {
		return
	}

	etherHeader := (*EtherHeader)(unsafe.Pointer(&packet.Buffer[0])) // Ethernet header pointer
	ipProto := Ntohs(etherHeader.Proto)                              // IP Protocol pointer

	if ipProto != ETH_P_IP { // If it's not IP protocol version 4
		return
	}

	ipHeaderSize := int(unsafe.Sizeof(IPHeader{}))
	if len(packet.Buffer) < etherHeaderSize+ipHeaderSize {
		return
	}

	ipHeaderOffset := etherHeaderSize
	ipHeader := (*IPHeader)(unsafe.Pointer(&packet.Buffer[ipHeaderOffset])) // IP header pointer

	if ipHeader.Protocol != IPPROTO_TCP {
		return
	}

	tcpHeaderSize := int(unsafe.Sizeof(TCPHeader{}))
	if len(packet.Buffer) < etherHeaderSize+ipHeaderSize+tcpHeaderSize {
		return
	}

	tcpHeaderOffset := ipHeaderOffset + int(ipHeader.HeaderLength()*4)
	tcpHeader := (*TCPHeader)(unsafe.Pointer(&packet.Buffer[tcpHeaderOffset])) // TCP header pointer

	tcpLen := int(Ntohs(ipHeader.TotalLength)) - int(ipHeader.HeaderLength()*4)
	padd := 0

	if tcpLen%2 != 0 {
		padd = 1
		packet.Buffer[tcpHeaderOffset+tcpLen] = 0
	}

	tcpHeader.Checksum = 0
	sum := 0

	for i := 0; i < tcpLen+padd; i += 2 {
		word16 := (uint16(packet.Buffer[tcpHeaderOffset+i]) << 8) + uint16(packet.Buffer[tcpHeaderOffset+i+1])
		sum += int(word16)
	}

	sum += int(Ntohs(*(*uint16)(unsafe.Pointer(&ipHeader.SourceAddr[0]))))
	sum += int(Ntohs(*(*uint16)(unsafe.Pointer(&ipHeader.SourceAddr[2]))))
	sum += int(Ntohs(*(*uint16)(unsafe.Pointer(&ipHeader.DestinationAddr[0]))))
	sum += int(Ntohs(*(*uint16)(unsafe.Pointer(&ipHeader.DestinationAddr[2]))))

	sum += int(IPPROTO_TCP) + tcpLen

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	sum = ^sum

	tcpHeader.Checksum = Htons(uint16(sum))
}

func RecalculateUDPChecksum(packet *IntermediateBuffer) {
	panic("not implmented yet")
}

func (a *NdisApi) IsNdiswanInterfaces(adapterName, ndiswanName string) bool {
	isNdiswanInterface := false

	// TODO:

	return isNdiswanInterface
}

func (a *NdisApi) IsNdiswanIP(adapterName string) bool {
	if a.IsWindows10OrGreater() && strings.Contains(adapterName, DEVICE_NDISWANIP) {
		return true
	}

	return a.IsNdiswanInterfaces(adapterName, REGSTR_COMPONENTID_NDISWANIP)
}

func (a *NdisApi) IsNdiswanIPv6(adapterName string) bool {
	if a.IsWindows10OrGreater() && strings.Contains(adapterName, DEVICE_NDISWANIPV6) {
		return true
	}

	return a.IsNdiswanInterfaces(adapterName, REGSTR_COMPONENTID_NDISWANIPV6)
}

func (a *NdisApi) IsNdiswanBh(adapterName string) bool {
	if a.IsWindows10OrGreater() && strings.Contains(adapterName, DEVICE_NDISWANBH) {
		return true
	}

	return a.IsNdiswanInterfaces(adapterName, REGSTR_COMPONENTID_NDISWANBH)
}

func (a *NdisApi) IsWindows10OrGreater() bool {
	var mod = syscall.NewLazyDLL("kernel32.dll")
	var proc = mod.NewProc("GetVersion")

	version, _, _ := proc.Call()
	major := byte(version)
	minor := byte(version >> 8)

	return major > 6 || (major == 6 && minor >= 2)
}
