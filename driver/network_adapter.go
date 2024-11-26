//go:build windows

package driver

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
		fmt.Println("error creating event for adapter", err.Error())
		return nil, err
	}
	adapter.packetEvent = A.NewSafeEvent(eventHandle)

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

func (na *NetworkAdapter) WaitEvent(timeout uint32) (uint32, error) {
	if na.packetEvent == nil {
		return 0, fmt.Errorf("event is not initialized")
	}
	return na.packetEvent.Wait(timeout)
}

func (na *NetworkAdapter) SignalEvent() error {
	return na.packetEvent.Signal()
}

func (na *NetworkAdapter) ResetEvent() error {
	return na.packetEvent.Reset()
}

func (na *NetworkAdapter) SetPacketEvent() error {
	return na.API.SetPacketEvent(na.CurrentMode.AdapterHandle, na.packetEvent.Handle)
}

func (na *NetworkAdapter) Release() {
	na.SignalEvent()

	na.CurrentMode.Flags = 0

	na.API.SetAdapterMode(&na.CurrentMode)
	na.API.FlushAdapterPacketQueue(na.CurrentMode.AdapterHandle)
}

func (na *NetworkAdapter) SetMode(flags uint32) error {
	na.CurrentMode.Flags = flags

	return na.API.SetAdapterMode(&na.CurrentMode)
}
func (na *NetworkAdapter) GetMode() A.AdapterMode {
	adapterMode := &A.AdapterMode{}
	err := na.API.GetAdapterMode(adapterMode)
	if err != nil {
		fmt.Println(err)
	}

	return *adapterMode
}

func (na *NetworkAdapter) GetAdapter() A.Handle {
	return na.CurrentMode.AdapterHandle
}
