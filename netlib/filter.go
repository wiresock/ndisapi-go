//go:build windows

package netlib

import (
	"net"
	"unsafe"

	A "github.com/wiresock/ndisapi-go"
)

type MultiRequestBuffer [unsafe.Sizeof(A.EtherMultiRequest{}) + unsafe.Sizeof(A.EthernetPacket{})*(A.MaximumPacketBlock-1)]byte

type FilterState uint32

const (
	Stopped FilterState = iota
	Starting
	Running
	Stopping
)

type Filter struct {
	networkInterfaceIndex *int
	sourceMacAddress      *net.HardwareAddr
	destMacAddress        *net.HardwareAddr
	ethernetType          *uint16
	sourceAddress         *net.IP
	destAddress           *net.IP
	sourcePort            *[2]uint16
	destinationPort       *[2]uint16
	protocol              *uint8
	direction             A.PacketDirection
	action                A.FilterAction
}

func NewFilter() *Filter {
	return &Filter{
		direction: A.PacketDirectionBoth,
		action:    A.FilterActionPass,
	}
}

func (f *Filter) GetDirection() A.PacketDirection {
	return f.direction
}

func (f *Filter) SetDirection(direction A.PacketDirection) *Filter {
	f.direction = direction
	return f
}

func (f *Filter) GetAction() A.FilterAction {
	return f.action
}

func (f *Filter) SetAction(action A.FilterAction) *Filter {
	f.action = action
	return f
}

func (f *Filter) GetNetworkInterfaceIndex() *int {
	return f.networkInterfaceIndex
}

func (f *Filter) SetNetworkInterfaceIndex(ifIndex int) *Filter {
	f.networkInterfaceIndex = &ifIndex
	return f
}

func (f *Filter) GetSourceHWAddress() *net.HardwareAddr {
	return f.sourceMacAddress
}

func (f *Filter) SetSourceHWAddress(address net.HardwareAddr) *Filter {
	f.sourceMacAddress = &address
	return f
}

func (f *Filter) GetDestHWAddress() *net.HardwareAddr {
	return f.destMacAddress
}

func (f *Filter) SetDestHWAddress(address net.HardwareAddr) *Filter {
	f.destMacAddress = &address
	return f
}

func (f *Filter) GetEtherType() *uint16 {
	return f.ethernetType
}

func (f *Filter) SetEtherType(etherType uint16) *Filter {
	f.ethernetType = &etherType
	return f
}

func (f *Filter) GetSourceAddress() *net.IP {
	return f.sourceAddress
}

func (f *Filter) SetSourceAddress(address net.IP) *Filter {
	f.sourceAddress = &address
	return f
}

func (f *Filter) GetDestAddress() *net.IP {
	return f.destAddress
}

func (f *Filter) SetDestAddress(address net.IP) *Filter {
	f.destAddress = &address
	return f
}

func (f *Filter) GetSourcePort() *[2]uint16 {
	return f.sourcePort
}

func (f *Filter) SetSourcePort(portRange [2]uint16) *Filter {
	f.sourcePort = &portRange
	return f
}

func (f *Filter) GetDestPort() *[2]uint16 {
	return f.destinationPort
}

func (f *Filter) SetDestPort(portRange [2]uint16) *Filter {
	f.destinationPort = &portRange
	return f
}

func (f *Filter) GetProtocol() *uint8 {
	return f.protocol
}

func (f *Filter) SetProtocol(protocol uint8) *Filter {
	f.protocol = &protocol
	return f
}
