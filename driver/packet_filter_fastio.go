//go:build windows

package driver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	A "github.com/wiresock/ndisapi-go"
	N "github.com/wiresock/ndisapi-go/netlib"

	"golang.org/x/sys/windows"
)

var _ PacketFilter = (*FastIOPacketFilter)(nil)

const fastIOSize = 0x300000

type requestStorageType [unsafe.Sizeof(A.IntermediateBuffer{}) * A.FastIOMaximumPacketBlock]byte
type fastIOStorageType [fastIOSize]byte

type FastIOPacketFilter struct {
	*A.NdisApi
	ctx context.Context

	adapters *A.TcpAdapterList

	filterIncomingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterOutgoingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterState          FilterState
	networkInterfaces    []*N.NetworkAdapter
	adapter              int

	packetBuffer []A.IntermediateBuffer

	waitOnPoll          bool
	writeAdapterRequest *requestStorageType
	writeMstcpRequest   *requestStorageType
	fastIO              []fastIOStorageType // shared fast i/o memory

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

func NewFastIOPacketFilter(ctx context.Context, api *A.NdisApi, adapters *A.TcpAdapterList, in, out func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction, waitOnPool bool) (*FastIOPacketFilter, error) {
	filter := &FastIOPacketFilter{
		NdisApi: api,
		ctx:     ctx,

		adapters: adapters,

		waitOnPoll:           waitOnPool,
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

func (f *FastIOPacketFilter) initFilter() error {
	f.packetBuffer = make([]A.IntermediateBuffer, A.FastIOMaximumPacketBlock)

	f.writeAdapterRequest = &requestStorageType{}
	f.writeMstcpRequest = &requestStorageType{}
	f.fastIO = make([]fastIOStorageType, 4)

	if f.waitOnPoll {
		if err := f.networkInterfaces[f.adapter].SetPacketEvent(); err != nil {
			f.packetBuffer = nil
			f.writeAdapterRequest = nil
			f.writeMstcpRequest = nil
			f.fastIO = nil
			return err
		}
	}

	fastIOSection := (*A.InitializeFastIOSection)(unsafe.Pointer(&f.fastIO[0]))

	if !f.InitializeFastIo(fastIOSection, fastIOSize) {
		f.packetBuffer = nil
		f.writeAdapterRequest = nil
		f.writeMstcpRequest = nil
		f.fastIO = nil
		return errors.New("failed to initialize fast IO")
	}

	for i := 1; i < 4; i++ {
		fastIOSection = (*A.InitializeFastIOSection)(unsafe.Pointer(&f.fastIO[i]))

		if !f.AddSecondaryFastIo(fastIOSection, fastIOSize) {
			f.packetBuffer = nil
			f.writeAdapterRequest = nil
			f.writeMstcpRequest = nil
			f.fastIO = nil
			return errors.New("failed to add secondary fast IO")
		}
	}

	if err := f.networkInterfaces[f.adapter].SetMode(A.MSTCP_FLAG_SENT_TUNNEL | A.MSTCP_FLAG_RECV_TUNNEL); err != nil {
		return err
	}

	return nil
}

func (f *FastIOPacketFilter) initializeNetworkInterfaces() error {
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

func (f *FastIOPacketFilter) Reconfigure() error {
	if f.filterState != FilterStateStopped {
		return errors.New("filter is not stopped")
	}

	f.networkInterfaces = nil
	if err := f.initializeNetworkInterfaces(); err != nil {
		return err
	}

	return nil
}

func (f *FastIOPacketFilter) StartFilter(adapterIdx int) error {
	if f.filterState != FilterStateStopped {
		return errors.New("filter is not stopped")
	}

	f.filterState = FilterStateStarting
	f.adapter = adapterIdx

	if err := f.initFilter(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(f.ctx)
	f.cancel = cancel

	f.filterState = FilterStateStarting

	// Start the working thread
	f.wg.Add(1)
	go f.filterWorkingThread(ctx)

	return nil
}

func (f *FastIOPacketFilter) Close() error {
	if f.filterState != FilterStateRunning {
		return errors.New("filter is not running")
	}

	f.filterState = FilterStateStopping
	f.networkInterfaces[f.adapter].Close()
	f.cancel()
	f.wg.Wait()
	f.filterState = FilterStateStopped
	return nil
}

func (f *FastIOPacketFilter) filterWorkingThread(ctx context.Context) {
	defer f.wg.Done()

	f.filterState = FilterStateRunning
	for {
		select {
		case <-f.ctx.Done():
			return
		default:
			var sentSuccess uint32
			var fastIOPacketsSuccess uint32

			writeAdapterRequest := (*[A.FastIOMaximumPacketBlock]*A.IntermediateBuffer)(unsafe.Pointer(&f.writeAdapterRequest[0]))[:]
			writeMstcpRequest := (*[A.FastIOMaximumPacketBlock]*A.IntermediateBuffer)(unsafe.Pointer(&f.writeMstcpRequest[0]))[:]

			fastIOSection := []*A.FastIOSection{
				(*A.FastIOSection)(unsafe.Pointer(&f.fastIO[0])),
				(*A.FastIOSection)(unsafe.Pointer(&f.fastIO[1])),
				(*A.FastIOSection)(unsafe.Pointer(&f.fastIO[2])),
				(*A.FastIOSection)(unsafe.Pointer(&f.fastIO[3])),
			}

			for {
				if f.filterState != FilterStateRunning {
					return
				}

				for _, i := range fastIOSection {
					if join := atomic.LoadUint32((*uint32)(unsafe.Pointer(&i.FastIOHeader.FastIOWriteUnion))); join > 0 {
						atomic.StoreUint32(&i.FastIOHeader.ReadInProgressFlag, 1)

						writeUnion := atomic.LoadUint32((*uint32)(unsafe.Pointer(&i.FastIOHeader.FastIOWriteUnion)))

						currentPacketsSuccess := (*A.FastIOWriteUnion)(unsafe.Pointer(&writeUnion)).GetNumberOfPackets()

						// Copy packets and reset section
						copy(f.packetBuffer[fastIOPacketsSuccess:], i.FastIOPackets[:currentPacketsSuccess-1])

						// For the last packet(s) wait for the write completion if in progress
						writeUnion = atomic.LoadUint32((*uint32)(unsafe.Pointer(&i.FastIOHeader.FastIOWriteUnion)))

						for (*A.FastIOWriteUnion)(unsafe.Pointer(&writeUnion)).GetWriteInProgressFlag() != 0 {
							writeUnion = atomic.LoadUint32((*uint32)(unsafe.Pointer(&i.FastIOHeader.FastIOWriteUnion)))
						}

						// Copy the last packet(s)
						copy(f.packetBuffer[fastIOPacketsSuccess+uint32(currentPacketsSuccess)-1:], i.FastIOPackets[currentPacketsSuccess-1:currentPacketsSuccess])

						if currentPacketsSuccess < i.FastIOHeader.FastIOWriteUnion.GetNumberOfPackets() {
							currentPacketsSuccess = i.FastIOHeader.FastIOWriteUnion.GetNumberOfPackets()
							copy(f.packetBuffer[fastIOPacketsSuccess+uint32(currentPacketsSuccess)-1:], i.FastIOPackets[currentPacketsSuccess-1:currentPacketsSuccess])
						}

						atomic.StoreUint32((*uint32)(unsafe.Pointer(&i.FastIOHeader.FastIOWriteUnion)), 0)
						atomic.StoreUint32(&i.FastIOHeader.ReadInProgressFlag, 0)

						fastIOPacketsSuccess += uint32(currentPacketsSuccess)
					}
				}
				fmt.Println(fastIOPacketsSuccess)

				var sendToAdapterNum uint32
				var sendToMstcpNum uint32

				for i := uint32(0); i < fastIOPacketsSuccess; i++ {
					packetAction := A.FilterActionPass

					if f.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
						if f.filterOutgoingPacket != nil {
							packetAction = f.filterOutgoingPacket(f.packetBuffer[i].HAdapterQLinkUnion.GetAdapter(), &f.packetBuffer[i])
						}
					} else {
						if f.filterIncomingPacket != nil {
							packetAction = f.filterIncomingPacket(f.packetBuffer[i].HAdapterQLinkUnion.GetAdapter(), &f.packetBuffer[i])
						}
					}

					// Place packet back into the flow if was allowed to
					if packetAction == A.FilterActionPass {
						if f.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
							writeAdapterRequest[sendToAdapterNum] = &f.packetBuffer[i]
							sendToAdapterNum++
						} else {
							writeMstcpRequest[sendToMstcpNum] = &f.packetBuffer[i]
							sendToMstcpNum++
						}
					} else if packetAction == A.FilterActionRedirect {
						if f.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_RECEIVE {
							writeAdapterRequest[sendToAdapterNum] = &f.packetBuffer[i]
							sendToAdapterNum++
						} else {
							writeMstcpRequest[sendToMstcpNum] = &f.packetBuffer[i]
							sendToMstcpNum++
						}
					}
				}

				if sendToAdapterNum > 0 {
					f.SendPacketsToAdaptersUnsorted(writeAdapterRequest, sendToAdapterNum, &sentSuccess)
				}

				if sendToMstcpNum > 0 {
					f.SendPacketsToMstcpUnsorted(writeMstcpRequest, sendToMstcpNum, &sentSuccess)
				}

				if fastIOPacketsSuccess == 0 {
					f.networkInterfaces[f.adapter].WaitEvent(windows.INFINITE)
					f.networkInterfaces[f.adapter].ResetEvent()
				}

				fastIOPacketsSuccess = 0
			}
		}
	}
}

func (f *FastIOPacketFilter) GetFilterState() FilterState {
	return f.filterState
}
