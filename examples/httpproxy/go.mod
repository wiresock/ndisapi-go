module http-proxy

go 1.23.2

require (
	github.com/google/gopacket v1.1.19
	github.com/wiresock/ndisapi-go v1.0.1
)

require golang.org/x/sys v0.28.0 // indirect

replace github.com/wiresock/ndisapi-go => ../..
