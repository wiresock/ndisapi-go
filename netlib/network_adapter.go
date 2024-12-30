//go:build windows

package netlib

import (
	"fmt"

	"golang.org/x/sys/windows"

	A "github.com/wiresock/ndisapi-go"
)

type NdisWanType int
type MacAddress [6]byte

const (
	NdisWanNone NdisWanType = iota
	NdisWanIP
	NdisWanIPv6
	NdisWanBH
)

type NetworkAdapter struct {
	API          *A.NdisApi
	HardwareAddr MacAddress
	InternalName string
	FriendlyName string
	Medium       uint32
	MTU          uint16
	CurrentMode  A.AdapterMode
	NdisWanType  NdisWanType

	packetEvent *A.SafeEvent
}

// NewNetworkAdapter constructs a NetworkAdapter instance using the provided parameters.
func NewNetworkAdapter(api *A.NdisApi, adapterHandle A.Handle, macAddr MacAddress, internalName, friendlyName string, medium uint32, mtu uint16) (*NetworkAdapter, error) {
	adapter := &NetworkAdapter{
		API:          api,
		HardwareAddr: macAddr,
		InternalName: internalName,
		FriendlyName: friendlyName,
		Medium:       medium,
		MTU:          mtu,
		CurrentMode: A.AdapterMode{
			AdapterHandle: adapterHandle,
			Flags:         0,
		},
	}

	eventHandle, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating event for adapter: %s", err.Error())
	}
	adapter.packetEvent = A.NewSafeEvent(eventHandle)

	// Initialize NDISWAN type
	if api.IsNdiswanIP(internalName) {
		adapter.NdisWanType = NdisWanIP
	} else if api.IsNdiswanIPv6(internalName) {
		adapter.NdisWanType = NdisWanIPv6
	} else if api.IsNdiswanBh(internalName) {
		adapter.NdisWanType = NdisWanBH
	} else {
		adapter.NdisWanType = NdisWanNone
	}

	return adapter, nil
}

// WaitEvent waits for the network interface event to be signaled.
func (na *NetworkAdapter) WaitEvent(timeout uint32) (uint32, error) {
	if na.packetEvent == nil {
		return 0, fmt.Errorf("event is not initialized")
	}
	return na.packetEvent.Wait(timeout)
}

// SignalEvent signals the packet event.
func (na *NetworkAdapter) SignalEvent() error {
	return na.packetEvent.Signal()
}

// ResetEvent resets the packet event.
func (na *NetworkAdapter) ResetEvent() error {
	return na.packetEvent.Reset()
}

// SetPacketEvent submits the packet event into the driver.
func (na *NetworkAdapter) SetPacketEvent() error {
	return na.API.SetPacketEvent(na.CurrentMode.AdapterHandle, na.packetEvent.Handle)
}

// Close stops filtering the network interface and tries to restore its original state.
func (na *NetworkAdapter) Close() {
	na.SignalEvent()

	// Reset adapter mode and flush the packet queue
	na.CurrentMode.Flags = 0

	na.API.SetAdapterMode(&na.CurrentMode)
	na.API.FlushAdapterPacketQueue(na.CurrentMode.AdapterHandle)
}

// SetMode sets the filtering mode for the network interface.
func (na *NetworkAdapter) SetMode(flags uint32) error {
	na.CurrentMode.Flags = flags

	return na.API.SetAdapterMode(&na.CurrentMode)
}

// GetMode returns the current adapter mode.
func (na *NetworkAdapter) GetMode() A.AdapterMode {
	adapterMode := &A.AdapterMode{}
	err := na.API.GetAdapterMode(adapterMode)
	if err != nil {
		fmt.Println(err)
	}

	return *adapterMode
}

// GetAdapter returns the network interface handle value.
func (na *NetworkAdapter) GetAdapter() A.Handle {
	return na.CurrentMode.AdapterHandle
}
