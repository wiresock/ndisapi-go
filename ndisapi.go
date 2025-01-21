//go:build windows

package ndisapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
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

var _ NdisApiInterface = (*NdisApi)(nil)

// NdisApi represents the NDISAPI driver interface.
type NdisApi struct {
	overlapped     windows.Overlapped
	fileHandle     windows.Handle
	isDriverLoaded bool
	bytesReturned  uint32
}

// NewNdisApi initializes a new instance of NdisApi.
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
	if err != nil {
		return nil, err
	}

	if fileHandle == windows.InvalidHandle {
		isLoadSuccessfully = false
	} else {
		overlapped.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
		if err == nil {
			isLoadSuccessfully = true
		}
	}

	ndisApi := &NdisApi{
		overlapped:     overlapped,
		fileHandle:     fileHandle,
		isDriverLoaded: isLoadSuccessfully,
	}

	return ndisApi, nil
}

// Close closes the NDISAPI driver handle and event handle.
func (a *NdisApi) Close() {
	if a.fileHandle != windows.InvalidHandle {
		windows.CloseHandle(a.fileHandle)
	}

	if a.overlapped.HEvent != 0 {
		windows.CloseHandle(a.overlapped.HEvent)
	}
}

// IsDriverLoaded checks if the NDISAPI driver is loaded successfully.
func (a *NdisApi) IsDriverLoaded() bool {
	return a.isDriverLoaded
}

// GetBytesReturned retrieves the number of bytes returned by the last DeviceIoControl call.
func (a *NdisApi) GetBytesReturned() uint32 {
	return a.bytesReturned
}

// DeviceIoControl sends a control code directly to the NDISAPI driver.
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

// GetVersion retrieves the NDISAPI driver version.
func (a *NdisApi) GetVersion() (uint32, error) {
	var nDriverAPIVersion uint32 = 0xFFFFFFFF

	err := a.DeviceIoControl(
		IOCTL_NDISRD_GET_VERSION,
		unsafe.Pointer(&nDriverAPIVersion),
		uint32(unsafe.Sizeof(nDriverAPIVersion)),
		unsafe.Pointer(&nDriverAPIVersion),
		uint32(unsafe.Sizeof(nDriverAPIVersion)),
		nil,
		nil,
	)

	if err != nil {
		return nDriverAPIVersion, err
	}

	return nDriverAPIVersion, nil
}

// GetIntermediateBufferPoolSize retrieves the effective size of the Windows Packet Filter internal intermediate buffer pool.
func (a *NdisApi) GetIntermediateBufferPoolSize(size uint32) error {
	return a.DeviceIoControl(
		IOCTL_NDISRD_QUERY_IB_POOL_SIZE,
		unsafe.Pointer(&size),
		uint32(unsafe.Sizeof(size)),
		unsafe.Pointer(&size),
		uint32(unsafe.Sizeof(size)),
		nil,
		nil,
	)
}
