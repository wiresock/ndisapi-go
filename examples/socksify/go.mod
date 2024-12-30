module socksify

go 1.23.2

require (
	github.com/google/gopacket v1.1.19
	github.com/wiresock/ndisapi-go v0.0.0-20241129122918-feb5578f8314
	golang.org/x/net v0.33.0
)

require golang.org/x/sys v0.28.0 // indirect

replace github.com/wiresock/ndisapi-go => ../..
