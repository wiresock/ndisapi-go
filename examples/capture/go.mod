module capture

go 1.23.2

toolchain go1.24.1

require github.com/wiresock/ndisapi-go v1.0.1

require github.com/google/gopacket v1.1.19

require (
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

replace github.com/wiresock/ndisapi-go => ../..
