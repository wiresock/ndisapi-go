//go:build windows && amd64

package ndisapi

import "unsafe"

// Pin the in-memory struct size of UnsortedReadSendRequest on amd64 as a
// runtime init guard against accidental layout changes: an 8-byte
// PINTERMEDIATE_BUFFER* followed by a 4-byte DWORD plus 4 bytes of trailing
// padding inserted by the C compiler to align the struct to pointer width.
// A compile-time assertion is not used here because go vet miscomputes
// unsafe.Sizeof for structs with trailing padding on Go 1.18–1.21.
func init() {
	var _v UnsortedReadSendRequest
	if unsafe.Sizeof(_v) != 16 {
		panic("UnsortedReadSendRequest has unexpected amd64 size")
	}
}
