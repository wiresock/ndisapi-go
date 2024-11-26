//go:build windows

package driver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	A "github.com/wiresock/ndisapi-go"
	N "github.com/wiresock/ndisapi-go/netlib"
)

type SimplePacketFilter struct {
	*A.NdisApi

	adapters *A.TcpAdapterList

	filterIncomingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterOutgoingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterState          N.FilterState
	networkInterfaces    []*NetworkAdapter

	adapter      int
	packetBuffer []A.IntermediateBuffer

	readRequest         *N.MultiRequestBuffer
	writeAdapterRequest *N.MultiRequestBuffer
	writeMstcpRequest   *N.MultiRequestBuffer

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func NewSimplePacketFilter(api *A.NdisApi, adapters *A.TcpAdapterList, in, out func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction) (*SimplePacketFilter, error) {
	filter := &SimplePacketFilter{
		NdisApi:  api,
		adapters: adapters,

		filterIncomingPacket: in,
		filterOutgoingPacket: out,
		filterState:          N.Stopped,
	}

	err := filter.initializeNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	return filter, nil
}

func (f *SimplePacketFilter) initFilter() error {
	f.packetBuffer = make([]A.IntermediateBuffer, A.MaximumPacketBlock)

	f.readRequest = &N.MultiRequestBuffer{}
	f.writeAdapterRequest = &N.MultiRequestBuffer{}
	f.writeMstcpRequest = &N.MultiRequestBuffer{}

	readRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.readRequest))
	writeAdapterRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.writeAdapterRequest))
	writeMstcpRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.writeMstcpRequest))

	adapterHandle := f.networkInterfaces[f.adapter].GetAdapter()
	readRequest.AdapterHandle = adapterHandle
	writeAdapterRequest.AdapterHandle = adapterHandle
	writeMstcpRequest.AdapterHandle = adapterHandle

	readRequest.PacketsNumber = A.MaximumPacketBlock

	readRequest.EthernetPackets = [A.MaximumPacketBlock]A.EthernetPacket{}

	for i := 0; i < A.MaximumPacketBlock; i++ {
		readRequest.EthernetPackets[i].Buffer = &f.packetBuffer[i]
	}

	if err := f.networkInterfaces[f.adapter].SetPacketEvent(); err != nil {
		f.packetBuffer = nil
		f.readRequest = nil
		f.writeAdapterRequest = nil
		f.writeMstcpRequest = nil
		return err
	}

	// Set adapter mode
	err := f.networkInterfaces[f.adapter].SetMode(A.MSTCP_FLAG_SENT_TUNNEL | A.MSTCP_FLAG_RECV_TUNNEL)
	if err != nil {
		return err
	}

	return nil
}

func (f *SimplePacketFilter) initializeNetworkInterfaces() error {
	for i := range f.adapters.AdapterCount {
		name := string(f.adapters.AdapterNameList[i][:])
		adapterHandle := f.adapters.AdapterHandle[i]
		currentAddress := f.adapters.CurrentAddress[i]
		medium := f.adapters.AdapterMediumList[i]
		mtu := f.adapters.MTU[i]

		friendlyName := f.ConvertWindows2000AdapterName(name)

		networkAdapter, err := NewNetworkAdapter(f.NdisApi, adapterHandle, currentAddress, name, friendlyName, medium, mtu)
		if err != nil {
			fmt.Println("error creating network adapter", err.Error())
			continue
		}
		f.networkInterfaces = append(f.networkInterfaces, networkAdapter)
	}

	return nil
}

func (f *SimplePacketFilter) ReleaseFilter() {
	f.networkInterfaces[f.adapter].Release()
}

func (f *SimplePacketFilter) Reconfigure() error {
	if f.filterState != N.Stopped {
		return errors.New("filter is not stopped")
	}

	f.networkInterfaces = nil
	if err := f.initializeNetworkInterfaces(); err != nil {
		return err
	}

	return nil
}

func (f *SimplePacketFilter) StartFilter(adapterIdx int) error {
	if f.filterState != N.Stopped {
		return errors.New("filter is not stopped")
	}

	f.filterState = N.Starting
	f.adapter = adapterIdx

	f.ctx, f.cancel = context.WithCancel(context.Background())

	if err := f.initFilter(); err != nil {
		return err
	}

	f.filterState = N.Starting

	// Start the working thread
	f.wg.Add(1)
	go f.filterWorkingThread()

	return nil
}

func (f *SimplePacketFilter) StopFilter() error {
	if f.filterState != N.Running {
		return errors.New("filter is not running")
	}

	f.filterState = N.Stopping

	f.cancel()

	f.wg.Wait()
	f.filterState = N.Stopped

	f.ReleaseFilter()

	return nil
}

func (f *SimplePacketFilter) filterWorkingThread() {
	defer f.wg.Done()

	f.filterState = N.Running

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
			readRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.readRequest))
			writeAdapterRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.writeAdapterRequest))
			writeMstcpRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.writeMstcpRequest))

			for f.filterState == N.Running {
				_, err := f.networkInterfaces[f.adapter].WaitEvent(windows.INFINITE)
				if err != nil {
					f.ctx.Done()
					return
				}

				err = f.networkInterfaces[f.adapter].ResetEvent()
				if err != nil {
					f.ctx.Done()
					return
				}

				for f.filterState == N.Running {
					if f.ReadPackets(readRequest) {
						break
					}

					for i := uint32(0); i < readRequest.PacketsSuccess; i++ {
						packetAction := A.FilterActionPass

						if f.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
							if f.filterOutgoingPacket != nil {
								packetAction = f.filterOutgoingPacket(readRequest.AdapterHandle, &f.packetBuffer[i])
							}
						} else {
							if f.filterIncomingPacket != nil {
								packetAction = f.filterIncomingPacket(readRequest.AdapterHandle, &f.packetBuffer[i])
							}
						}

						if packetAction == A.FilterActionPass {
							if f.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
								writeAdapterRequest.EthernetPackets[writeAdapterRequest.PacketsNumber].Buffer = &f.packetBuffer[i]
								writeAdapterRequest.PacketsNumber++
							} else {
								writeMstcpRequest.EthernetPackets[writeMstcpRequest.PacketsNumber].Buffer = &f.packetBuffer[i]
								writeMstcpRequest.PacketsNumber++
							}
						} else if packetAction == A.FilterActionRedirect {
							if f.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_RECEIVE {
								writeAdapterRequest.EthernetPackets[writeAdapterRequest.PacketsNumber].Buffer = &f.packetBuffer[i]
								writeAdapterRequest.PacketsNumber++
							} else {
								writeMstcpRequest.EthernetPackets[writeMstcpRequest.PacketsNumber].Buffer = &f.packetBuffer[i]
								writeMstcpRequest.PacketsNumber++
							}
						}
					}

					if writeAdapterRequest.PacketsNumber > 0 {
						_ = f.SendPacketsToAdapter(writeAdapterRequest)
						writeAdapterRequest.PacketsNumber = 0
					}

					if writeMstcpRequest.PacketsNumber > 0 {
						_ = f.SendPacketsToMstcp(writeMstcpRequest)
						writeMstcpRequest.PacketsNumber = 0
					}

					readRequest.PacketsSuccess = 0
				}
			}
		}
	}
}

func (f *SimplePacketFilter) GetInterfaceNamesList() []string {
	names := make([]string, len(f.networkInterfaces))
	for i, iface := range f.networkInterfaces {
		names[i] = iface.FriendlyName
	}
	return names
}

func (f *SimplePacketFilter) GetInterfaceHWList() []MacAddress {
	names := make([]MacAddress, len(f.networkInterfaces))
	for i, iface := range f.networkInterfaces {
		names[i] = iface.HardwareAddr
	}
	return names
}

func (f *SimplePacketFilter) GetFilterState() N.FilterState {
	return f.filterState
}
