//go:build windows

package driver

import (
	"bytes"
	"net"

	A "github.com/wiresock/ndisapi-go"
)

type Filter struct {
	*A.StaticFilter
	AdapterHandle         A.Handle
	SourceMacAddress      net.HardwareAddr
	DestinationMacAddress net.HardwareAddr
	EthernetType          uint16
	SourceAddress         net.IPNet
	DestinationAddress    net.IPNet
	SourcePort            [2]uint16
	DestinationPort       [2]uint16
	Protocol              uint8
	Direction             PacketDirection
	Action                A.FilterAction
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
