module proxifyre

go 1.23.2

require github.com/wiresock/ndisapi-go v1.0.1

require (
	github.com/google/gopacket v1.1.19
	github.com/wzshiming/socks5 v0.5.1
	golang.org/x/sys v0.28.0
)

replace github.com/wiresock/ndisapi-go => ../..
