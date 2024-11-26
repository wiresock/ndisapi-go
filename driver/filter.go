//go:build windows

package driver

import (
	"net"
	"unsafe"

	A "github.com/wiresock/ndisapi-go"
)

type MultiRequestBuffer [unsafe.Sizeof(A.EtherMultiRequest{}) + unsafe.Sizeof(A.EthernetPacket{})*(A.MaximumPacketBlock-1)]byte

type FilterState uint32

const (
	FilterStateStopped FilterState = iota
	FilterStateStarting
	FilterStateRunning
	FilterStateStopping
)

type Filter struct {
	networkInterfaceIndex *int              // network interface index
	sourceMacAddress      *net.HardwareAddr // source MAC address
	destMacAddress        *net.HardwareAddr // destination MAC address
	ethernetType          *uint16           // Ethernet type
	sourceAddress         *net.IP           // source IP address
	destAddress           *net.IP           // destination IP address
	sourcePort            *[2]uint16        // source port (TCP/UDP only)
	destinationPort       *[2]uint16        // destination port (TCP/UDP only)
	protocol              *uint8            // IP protocol
	direction             A.PacketDirection // packet direction
	action                A.FilterAction    // filter action
}

func NewFilter() *Filter {
	return &Filter{
		direction: A.PacketDirectionBoth,
		action:    A.FilterActionPass,
	}
}

// Getter for the direction
func (f *Filter) GetDirection() A.PacketDirection {
	return f.direction
}

// Setter for the filter direction
func (f *Filter) SetDirection(direction A.PacketDirection) *Filter {
	f.direction = direction
	return f
}

// Getter for the action
func (f *Filter) GetAction() A.FilterAction {
	return f.action
}

// Setter for the action
func (f *Filter) SetAction(action A.FilterAction) *Filter {
	f.action = action
	return f
}

// Getter for the network interface index
func (f *Filter) GetNetworkInterfaceIndex() *int {
	return f.networkInterfaceIndex
}

// Setter for the filter interface index
func (f *Filter) SetNetworkInterfaceIndex(ifIndex int) *Filter {
	f.networkInterfaceIndex = &ifIndex
	return f
}

// Getter for source MAC address
func (f *Filter) GetSourceHWAddress() *net.HardwareAddr {
	return f.sourceMacAddress
}

// Setter for the source MAC address
func (f *Filter) SetSourceHWAddress(address net.HardwareAddr) *Filter {
	f.sourceMacAddress = &address
	return f
}

// Getter for the destination MAC address
func (f *Filter) GetDestHWAddress() *net.HardwareAddr {
	return f.destMacAddress
}

// Setter for the destination MAC address
func (f *Filter) SetDestHWAddress(address net.HardwareAddr) *Filter {
	f.destMacAddress = &address
	return f
}

// Getter for the ethernet type
func (f *Filter) GetEtherType() *uint16 {
	return f.ethernetType
}

// Setter for the ethernet type
func (f *Filter) SetEtherType(etherType uint16) *Filter {
	f.ethernetType = &etherType
	return f
}

// Getter for source IP address
func (f *Filter) GetSourceAddress() *net.IP {
	return f.sourceAddress
}

// Setter for the source IP address
func (f *Filter) SetSourceAddress(address net.IP) *Filter {
	f.sourceAddress = &address
	return f
}

// Getter for the destination IP address
func (f *Filter) GetDestAddress() *net.IP {
	return f.destAddress
}

// Setter for the destination IP address
func (f *Filter) SetDestAddress(address net.IP) *Filter {
	f.destAddress = &address
	return f
}

// Getter for the source port
func (f *Filter) GetSourcePort() *[2]uint16 {
	return f.sourcePort
}

// Setter for the source port
func (f *Filter) SetSourcePort(portRange [2]uint16) *Filter {
	f.sourcePort = &portRange
	return f
}

// Getter for the destination port
func (f *Filter) GetDestPort() *[2]uint16 {
	return f.destinationPort
}

// Setter for the destination port
func (f *Filter) SetDestPort(portRange [2]uint16) *Filter {
	f.destinationPort = &portRange
	return f
}

// Getter for the IP protocol
func (f *Filter) GetProtocol() *uint8 {
	return f.protocol
}

// Setter for the IP protocol
func (f *Filter) SetProtocol(protocol uint8) *Filter {
	f.protocol = &protocol
	return f
}
