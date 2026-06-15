//go:build windows

package ndisapi

import (
	"testing"
	"unsafe"
)

// TestMarshalStaticFilterTable verifies that marshalStaticFilterTable lays the filters out
// contiguously starting at offset 8 - the exact layout GetPacketFilterTable reads back - and
// that the slice header is NOT what ends up on the wire. This is the regression test for the
// SetPacketFilterTable slice-marshaling bug and needs no live driver.
func TestMarshalStaticFilterTable(t *testing.T) {
	const n = 3

	table := &StaticFilterTable{
		TableSize:     n,
		StaticFilters: make([]StaticFilter, n),
	}
	for i := 0; i < n; i++ {
		// Distinct, easily recognizable sentinel values per filter.
		table.StaticFilters[i] = StaticFilter{
			Adapter:        Handle{byte(i + 1), 0, 0, 0, 0, 0, 0, 0},
			DirectionFlags: uint32(0x1000 + i),
			FilterAction:   uint32(0x2000 + i),
			ValidFields:    uint32(0x3000 + i),
			PacketsIn:      uint64(0xAAAA0000) + uint64(i),
		}
	}

	// Pin the driver contract: the STATIC_FILTER array must begin at offset 8 (TableSize +
	// Padding). The marshaling and the read path both rely on this exact layout.
	if staticFilterTableHeaderSize != 8 {
		t.Fatalf("staticFilterTableHeaderSize = %d, want 8", staticFilterTableHeaderSize)
	}

	buf := marshalStaticFilterTable(table)

	// Buffer size must match the formula used by GetPacketFilterTable.
	wantSize := int(staticFilterTableHeaderSize) + n*int(unsafe.Sizeof(StaticFilter{}))
	if len(buf) != wantSize {
		t.Fatalf("buffer size = %d, want %d", len(buf), wantSize)
	}

	// Header: TableSize at offset 0.
	if got := *(*uint32)(unsafe.Pointer(&buf[0])); got != n {
		t.Fatalf("header TableSize = %d, want %d", got, n)
	}

	// Each filter must be readable contiguously after the header, exactly mirroring the read
	// path in GetPacketFilterTable. StaticFilter has no pointers/slices/maps, so it is
	// comparable - compare the whole struct, not a hand-picked subset of fields.
	for i := 0; i < n; i++ {
		offset := int(staticFilterTableHeaderSize) + i*int(unsafe.Sizeof(StaticFilter{}))
		got := *(*StaticFilter)(unsafe.Pointer(&buf[offset]))
		want := table.StaticFilters[i]
		if got != want {
			t.Errorf("filter[%d] mismatch:\n got = %+v\nwant = %+v", i, got, want)
		}
	}

	// Guard against the original bug: the bytes right after the header must be the first real
	// filter, not a slice header. With the bug, that region would hold the slice data pointer,
	// so the first filter's Adapter (our sentinel {1,0,...}) would not survive.
	first := *(*StaticFilter)(unsafe.Pointer(&buf[staticFilterTableHeaderSize]))
	if first.Adapter != (Handle{1, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("region after header does not hold the first filter (slice-header bug): Adapter = %v", first.Adapter)
	}
}

// TestMarshalStaticFilterTableLengthIsSourceOfTruth verifies that the slice length - not the
// caller-supplied TableSize field - determines how many filters are marshaled, so a stale or
// wrong TableSize can never produce a header count that disagrees with the filter data.
func TestMarshalStaticFilterTableLengthIsSourceOfTruth(t *testing.T) {
	table := &StaticFilterTable{
		TableSize: 5, // deliberately wrong - only 2 filters actually present
		StaticFilters: []StaticFilter{
			{Adapter: Handle{1, 0, 0, 0, 0, 0, 0, 0}, FilterAction: 0x2000},
			{Adapter: Handle{2, 0, 0, 0, 0, 0, 0, 0}, FilterAction: 0x2001},
		},
	}

	buf := marshalStaticFilterTable(table)

	// Header count must reflect the slice length (2), not the bogus TableSize (5).
	if got := *(*uint32)(unsafe.Pointer(&buf[0])); got != 2 {
		t.Fatalf("header TableSize = %d, want 2 (slice length)", got)
	}

	// Buffer must be sized for 2 filters, not 5.
	wantSize := int(staticFilterTableHeaderSize) + 2*int(unsafe.Sizeof(StaticFilter{}))
	if len(buf) != wantSize {
		t.Fatalf("buffer size = %d, want %d (2 filters)", len(buf), wantSize)
	}

	// The two real filters must still be laid out correctly after the header.
	for i := 0; i < 2; i++ {
		offset := int(staticFilterTableHeaderSize) + i*int(unsafe.Sizeof(StaticFilter{}))
		got := *(*StaticFilter)(unsafe.Pointer(&buf[offset]))
		if got != table.StaticFilters[i] {
			t.Errorf("filter[%d] mismatch:\n got = %+v\nwant = %+v", i, got, table.StaticFilters[i])
		}
	}
}

// TestMarshalStaticFilterTableEmpty ensures a zero-filter table marshals to just the 8-byte
// header without panicking.
func TestMarshalStaticFilterTableEmpty(t *testing.T) {
	table := &StaticFilterTable{TableSize: 0, StaticFilters: nil}
	buf := marshalStaticFilterTable(table)

	wantSize := int(staticFilterTableHeaderSize)
	if len(buf) != wantSize {
		t.Fatalf("empty buffer size = %d, want %d", len(buf), wantSize)
	}
	if got := *(*uint32)(unsafe.Pointer(&buf[0])); got != 0 {
		t.Fatalf("header TableSize = %d, want 0", got)
	}
}
