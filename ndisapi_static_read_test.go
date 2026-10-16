//go:build windows

package ndisapi

import (
	"errors"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type testDeviceIoControl func(windows.Handle, uint32, *byte, uint32, *byte, uint32, *uint32, *windows.Overlapped) error

func mockDeviceIoControl(t *testing.T, call testDeviceIoControl) {
	t.Helper()
	previous := deviceIoControl
	deviceIoControl = call
	t.Cleanup(func() { deviceIoControl = previous })
}

// Exercise both exported readers; only the Windows syscall is replaced.
func forEachStaticTableReader(t *testing.T, test func(*testing.T, bool)) {
	t.Helper()
	t.Run("read", func(t *testing.T) { test(t, false) })
	t.Run("reset_stats", func(t *testing.T) { test(t, true) })
}

func readStaticTable(api *NdisApi, reset bool, capacity uint32) (*StaticFilterTable, error) {
	if reset {
		return api.GetPacketFilterTableResetStats()
	}
	return api.GetPacketFilterTable(capacity)
}

func staticTableDriver(t *testing.T, reset bool, capacity uint32, read func(*byte, uint32, *uint32) error) testDeviceIoControl {
	t.Helper()
	queried := !reset
	return func(_ windows.Handle, code uint32, in *byte, sizeIn uint32, out *byte, sizeOut uint32, returned *uint32, overlapped *windows.Overlapped) error {
		if in != nil || sizeIn != 0 || out == nil || returned == nil || overlapped != nil {
			t.Fatal("unexpected table IOCTL buffer arguments")
		}
		if code == IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE {
			if queried || sizeOut != 4 {
				t.Fatal("unexpected table size query")
			}
			queried = true
			*(*uint32)(unsafe.Pointer(out)) = capacity
			*returned = 4
			return nil
		}
		wantCode := uint32(IOCTL_NDISRD_GET_PACKET_FILTERS)
		if reset {
			wantCode = IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS
		}
		if code != wantCode || !queried {
			t.Fatalf("table read code %#x before size query completed: %v", code, queried)
		}
		wantSize := uint32(8) + capacity*uint32(unsafe.Sizeof(StaticFilter{}))
		if sizeOut != wantSize {
			t.Fatalf("output buffer size = %d, want %d (native header plus inline filters)", sizeOut, wantSize)
		}
		if got := *(*uint32)(unsafe.Pointer(out)); got != capacity {
			t.Errorf("input header count = %d, want capacity %d", got, capacity)
		}
		return read(out, sizeOut, returned)
	}
}

func TestStaticTableReadersDecodeReturnedCountAndCounters(t *testing.T) {
	forEachStaticTableReader(t, func(t *testing.T, reset bool) {
		// The table shrank after capacity was queried. The returned header, not
		// the capacity, determines how many entries callers receive.
		want := StaticFilter{
			Adapter: Handle{0x12, 0x34}, DirectionFlags: 3, FilterAction: FILTER_PACKET_PASS,
			LastReset: 123, PacketsIn: 0x1122334455667788, BytesIn: 9876,
			PacketsOut: 43, BytesOut: 54321,
		}
		mockDeviceIoControl(t, staticTableDriver(t, reset, 3, func(out *byte, _ uint32, returned *uint32) error {
			*(*uint32)(unsafe.Pointer(out)) = 1
			buffer := (*[8 + unsafe.Sizeof(StaticFilter{})]byte)(unsafe.Pointer(out))
			*(*StaticFilter)(unsafe.Pointer(&buffer[8])) = want
			*returned = 8 + uint32(unsafe.Sizeof(StaticFilter{}))
			return nil
		}))
		api := &NdisApi{}
		got, err := readStaticTable(api, reset, 3)
		if err != nil {
			t.Fatal(err)
		}
		if got.TableSize != 1 || !reflect.DeepEqual(got.StaticFilters, []StaticFilter{want}) {
			t.Fatalf("returned table = %+v, want exactly the returned filter %+v", got, want)
		}
		if api.GetBytesReturned() != 8+uint32(unsafe.Sizeof(StaticFilter{})) {
			t.Fatal("GetBytesReturned did not retain the table IOCTL byte count")
		}
	})
}

func TestStaticTableReadersAcceptEmptyTable(t *testing.T) {
	forEachStaticTableReader(t, func(t *testing.T, reset bool) {
		mockDeviceIoControl(t, staticTableDriver(t, reset, 0, func(_ *byte, _ uint32, returned *uint32) error {
			*returned = 8
			return nil
		}))
		got, err := readStaticTable(&NdisApi{}, reset, 0)
		if err != nil || got == nil || got.TableSize != 0 || len(got.StaticFilters) != 0 {
			t.Fatalf("empty table = %+v, err = %v", got, err)
		}
	})
}

func TestStaticTableReadersRejectMalformedResponse(t *testing.T) {
	filterSize := uint32(unsafe.Sizeof(StaticFilter{}))
	cases := []struct {
		name         string
		count, bytes uint32
	}{
		{"missing_header", 0, 0},
		{"short_header", 0, 7},
		{"truncated_filter", 1, 8 + filterSize - 1},
		{"count_exceeds_capacity", 2, 8 + filterSize},
		{"bytes_exceed_capacity", 1, 9 + filterSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachStaticTableReader(t, func(t *testing.T, reset bool) {
				mockDeviceIoControl(t, staticTableDriver(t, reset, 1, func(out *byte, _ uint32, returned *uint32) error {
					*(*uint32)(unsafe.Pointer(out)) = tc.count
					*returned = tc.bytes
					return nil
				}))
				if got, err := readStaticTable(&NdisApi{}, reset, 1); err == nil || got != nil {
					t.Fatalf("malformed response accepted: table = %+v, err = %v", got, err)
				}
			})
		})
	}
}

func TestStaticTableReadersPropagateDriverError(t *testing.T) {
	forEachStaticTableReader(t, func(t *testing.T, reset bool) {
		want := windows.ERROR_INSUFFICIENT_BUFFER // Table grew since capacity was queried.
		mockDeviceIoControl(t, staticTableDriver(t, reset, 1, func(_ *byte, _ uint32, _ *uint32) error {
			return want
		}))
		if got, err := readStaticTable(&NdisApi{}, reset, 1); got != nil || !errors.Is(err, want) {
			t.Fatalf("table = %+v, err = %v, want nil and %v", got, err, want)
		}
	})
}

func TestGetPacketFilterTableResetStatsPropagatesSizeQueryError(t *testing.T) {
	mockDeviceIoControl(t, func(_ windows.Handle, code uint32, _ *byte, _ uint32, _ *byte, _ uint32, _ *uint32, _ *windows.Overlapped) error {
		if code != IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE {
			t.Fatalf("first IOCTL = %#x, want table size query", code)
		}
		return windows.ERROR_ACCESS_DENIED
	})
	if got, err := (&NdisApi{}).GetPacketFilterTableResetStats(); got != nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("table = %+v, err = %v, want size query error", got, err)
	}
}

func TestGetPacketFilterTableResetStatsRejectsShortSizeResponse(t *testing.T) {
	mockDeviceIoControl(t, func(_ windows.Handle, code uint32, _ *byte, _ uint32, out *byte, _ uint32, returned *uint32, _ *windows.Overlapped) error {
		if code != IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE {
			t.Fatal("invalid size response reached the reset IOCTL")
		}
		*(*uint32)(unsafe.Pointer(out)) = 0
		*returned = 0
		return nil
	})
	if got, err := (&NdisApi{}).GetPacketFilterTableResetStats(); got != nil || err == nil {
		t.Fatalf("short size response accepted: table = %+v, err = %v", got, err)
	}
}

func TestStaticTableReadersRejectOverflow(t *testing.T) {
	forEachStaticTableReader(t, func(t *testing.T, reset bool) {
		const capacity = ^uint32(0)
		mockDeviceIoControl(t, func(_ windows.Handle, code uint32, _ *byte, _ uint32, out *byte, _ uint32, returned *uint32, _ *windows.Overlapped) error {
			if reset && code == IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE {
				*(*uint32)(unsafe.Pointer(out)) = capacity
				*returned = 4
				return nil
			}
			t.Fatal("overflowed table capacity reached DeviceIoControl")
			return nil
		})
		if got, err := readStaticTable(&NdisApi{}, reset, capacity); got != nil || err == nil {
			t.Fatalf("overflowed capacity accepted: table = %+v, err = %v", got, err)
		}
	})
}
