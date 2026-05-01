//go:build windows && amd64

package ndisapi

import "unsafe"

// Pin the on-the-wire size of UnsortedReadSendRequest on amd64: an 8-byte
// PINTERMEDIATE_BUFFER* followed by a 4-byte DWORD plus 4 bytes of trailing
// padding inserted by the C compiler to align the struct to pointer width.
// This is checked at init time because go vet miscomputes unsafe.Sizeof for
// structs with trailing padding across all Go versions tested in CI (1.18–1.21),
// making a compile-time array-length assertion unreliable.
func init() {
	if unsafe.Sizeof(UnsortedReadSendRequest{}) != 16 {
		panic("UnsortedReadSendRequest has unexpected amd64 size")
	}
}
