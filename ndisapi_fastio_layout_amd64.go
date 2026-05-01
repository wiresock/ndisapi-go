//go:build windows && amd64 && go1.20

package ndisapi

import "unsafe"

// Pin the on-the-wire size of UnsortedReadSendRequest on x64: an 8-byte
// PINTERMEDIATE_BUFFER* followed by a 4-byte DWORD plus 4 bytes of trailing
// padding inserted by the C compiler to align the struct to pointer width.
// Adding any new field would change the size and trip this assertion. On x86
// the struct is already pointer-aligned with no trailing padding, so the
// per-field offset/size assertions in ndisapi_fastio.go already cover every
// byte of the struct and a separate total-size check is unnecessary.
//
// A package-level var (not a composite literal) is used so that unsafe.Sizeof
// correctly accounts for trailing struct padding. The assignment to [16]byte
// catches any size mismatch at compile time without subtraction.
var _unsortedReadSendRequestSizeCheck UnsortedReadSendRequest
var _ [16]byte = [unsafe.Sizeof(_unsortedReadSendRequestSizeCheck)]byte{}
