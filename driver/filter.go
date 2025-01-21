//go:build windows

package driver

import (
	"bytes"
	"net"

	A "github.com/wiresock/ndisapi-go"
)

type Filter struct {
	*A.StaticFilter
	AdapterHandle         A.Handle         // adapter handle
	SourceMacAddress      net.HardwareAddr // source MAC address
	DestinationMacAddress net.HardwareAddr // destination MAC address
	EthernetType          uint16           // Ethernet type
	SourceAddress         net.IPNet        // source IP
	DestinationAddress    net.IPNet        // destination IP
	SourcePort            [2]uint16        // source port (TCP/UDP only)
	DestinationPort       [2]uint16        // destination port (TCP/UDP only)
	Protocol              uint8            // IP protocol
	Direction             PacketDirection  // packet direction
	Action                A.FilterAction   // filter action
}

// Equal checks if two filters are equal
func (f *Filter) Equal(other *Filter) bool {
	if f == other {
		return true
	}
	if other == nil {
		return false
	}
	return f.AdapterHandle == other.AdapterHandle &&
		bytes.Equal(f.SourceMacAddress, other.SourceMacAddress) &&
		bytes.Equal(f.DestinationMacAddress, other.DestinationMacAddress) &&
		f.EthernetType == other.EthernetType &&
		f.SourceAddress.String() == other.SourceAddress.String() &&
		f.DestinationAddress.String() == other.DestinationAddress.String() &&
		f.SourcePort == other.SourcePort &&
		f.DestinationPort == other.DestinationPort &&
		f.Protocol == other.Protocol &&
		f.Direction == other.Direction &&
		f.Action == other.Action
}
