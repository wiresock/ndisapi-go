//go:build windows && amd64 && !go1.20

package ndisapi

import "unsafe"

// Go 1.18/1.19 vet miscomputes unsafe.Sizeof for UnsortedReadSendRequest in
// array-length declarations by omitting the trailing amd64 padding. Keep these
// versions on a runtime guard so go test can pass while still checking the ABI
// before any package API is used.
func init() {
	if unsafe.Sizeof(UnsortedReadSendRequest{}) != 16 {
		panic("UnsortedReadSendRequest has unexpected amd64 size")
	}
}
