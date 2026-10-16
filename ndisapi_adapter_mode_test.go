//go:build windows

package ndisapi

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestGetAdapterModeQueriesWithoutSettingMode(t *testing.T) {
	adapter := Handle{0x12, 0x34}
	mockDeviceIoControl(t, func(_ windows.Handle, code uint32, in *byte, sizeIn uint32, out *byte, sizeOut uint32, returned *uint32, _ *windows.Overlapped) error {
		if code != IOCTL_NDISRD_GET_ADAPTER_MODE {
			t.Fatalf("GetAdapterMode IOCTL = %#x, want read-only GET %#x", code, uint32(IOCTL_NDISRD_GET_ADAPTER_MODE))
		}
		if in != out || sizeIn != uint32(unsafe.Sizeof(AdapterMode{})) || sizeOut != sizeIn {
			t.Fatal("invalid adapter mode IOCTL buffers")
		}
		mode := (*AdapterMode)(unsafe.Pointer(in))
		if mode.AdapterHandle != adapter {
			t.Fatal("adapter handle was not sent to the driver")
		}
		mode.Flags = 3
		*returned = sizeOut
		return nil
	})
	mode := AdapterMode{AdapterHandle: adapter}
	if err := (&NdisApi{}).GetAdapterMode(&mode); err != nil || mode.Flags != 3 {
		t.Fatalf("mode = %+v, err = %v", mode, err)
	}
}
