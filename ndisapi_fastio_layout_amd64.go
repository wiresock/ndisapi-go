//go:build windows && amd64

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
// A package-level variable is used here (rather than a struct literal) because
// `go vet` in Go 1.18 and 1.19 mis-evaluates `unsafe.Sizeof(StructLiteral{})`
// as a constant that omits trailing struct padding (returning 12 instead of 16
// here), which would cause the subtraction below to overflow `uintptr` and
// fail vet even though the compiled binary lays the struct out correctly.
// Computing `Sizeof` from a typed identifier avoids that constant-folding path.
var _unsortedReadSendRequestForSizeAssert UnsortedReadSendRequest
var _ [0]byte = [unsafe.Sizeof(_unsortedReadSendRequestForSizeAssert) - 16]byte{}

