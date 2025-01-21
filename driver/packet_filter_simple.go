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

type MultiRequestBuffer [unsafe.Sizeof(A.EtherMultiRequest{}) + unsafe.Sizeof(A.EthernetPacket{})*(A.MaximumPacketBlock-1)]byte

var _ PacketFilter = (*SimplePacketFilter)(nil)

type SimplePacketFilter struct {
	*A.NdisApi

	adapters *A.TcpAdapterList

	filterIncomingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterOutgoingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterState          FilterState
	networkInterfaces    []*N.NetworkAdapter
	adapter              int

	packetBuffer []A.IntermediateBuffer

	readRequest         *MultiRequestBuffer
	writeAdapterRequest *MultiRequestBuffer
	writeMstcpRequest   *MultiRequestBuffer

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
		filterState:          FilterStateStopped,
	}

	err := filter.initializeNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	return filter, nil
}

func (f *SimplePacketFilter) initFilter() error {
	f.packetBuffer = make([]A.IntermediateBuffer, A.MaximumPacketBlock)

	f.readRequest = &MultiRequestBuffer{}
	f.writeAdapterRequest = &MultiRequestBuffer{}
	f.writeMstcpRequest = &MultiRequestBuffer{}

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
	for i := 0; i < int(f.adapters.AdapterCount); i++ {
		name := string(f.adapters.AdapterNameList[i][:])
		adapterHandle := f.adapters.AdapterHandle[i]
		currentAddress := f.adapters.CurrentAddress[i]
		medium := f.adapters.AdapterMediumList[i]
		mtu := f.adapters.MTU[i]

		friendlyName := f.ConvertWindows2000AdapterName(name)

		networkAdapter, err := N.NewNetworkAdapter(f.NdisApi, adapterHandle, currentAddress, name, friendlyName, medium, mtu)
		if err != nil {
			fmt.Println("error creating network adapter", err.Error())
			continue
		}
		f.networkInterfaces = append(f.networkInterfaces, networkAdapter)
	}

	return nil
}

func (f *SimplePacketFilter) Close() {
	f.networkInterfaces[f.adapter].Close()
}

func (f *SimplePacketFilter) Reconfigure() error {
	if f.filterState != FilterStateStopped {
		return errors.New("filter is not stopped")
	}

	f.networkInterfaces = nil
	if err := f.initializeNetworkInterfaces(); err != nil {
		return err
	}

	return nil
}

func (f *SimplePacketFilter) StartFilter(adapterIdx int) error {
	if f.filterState != FilterStateStopped {
		return errors.New("filter is not stopped")
	}

	f.filterState = FilterStateStarting
	f.adapter = adapterIdx

	f.ctx, f.cancel = context.WithCancel(context.Background())

	if err := f.initFilter(); err != nil {
		return err
	}

	f.filterState = FilterStateStarting

	// Start the working thread
	f.wg.Add(1)
	go f.filterWorkingThread()

	return nil
}

func (f *SimplePacketFilter) StopFilter() error {
	if f.filterState != FilterStateRunning {
		return errors.New("filter is not running")
	}

	f.filterState = FilterStateStopping

	f.cancel()

	f.wg.Wait()
	f.filterState = FilterStateStopped

	f.Close()

	return nil
}

func (f *SimplePacketFilter) filterWorkingThread() {
	defer f.wg.Done()

	f.filterState = FilterStateRunning

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
			readRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.readRequest))
			writeAdapterRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.writeAdapterRequest))
			writeMstcpRequest := (*A.EtherMultiRequest)(unsafe.Pointer(f.writeMstcpRequest))

			for f.filterState == FilterStateRunning {
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

				for f.filterState == FilterStateRunning {
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

func (f *SimplePacketFilter) GetFilterState() FilterState {
	return f.filterState
}
