//go:build windows && amd64 && go1.19

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
// Gated on go1.19+ because Go 1.18's `vet` evaluates
// `unsafe.Sizeof(StructLiteral{})` without including trailing struct padding
// (returns 12 instead of 16 here) and then mis-folds the resulting subtraction
// to a negative uintptr constant, which fails vet even though the actual
// compiled binary lays the struct out correctly.
var _ [0]byte = [unsafe.Sizeof(UnsortedReadSendRequest{}) - 16]byte{}

