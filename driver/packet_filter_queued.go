//go:build windows

package driver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	A "github.com/wiresock/ndisapi-go"
	N "github.com/wiresock/ndisapi-go/netlib"

	"golang.org/x/sys/windows"
)

var _ PacketFilter = (*QueuedPacketFilter)(nil)

type QueuedPacketFilter struct {
	*A.NdisApi

	adapters *A.TcpAdapterList

	filterIncomingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterOutgoingPacket func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction
	filterState          FilterState
	networkInterfaces    []*N.NetworkAdapter
	adapter              int

	wg         sync.WaitGroup
	cancelFunc context.CancelFunc

	packetReadChan         chan *PacketBlock
	packetProcessChan      chan *PacketBlock
	packetWriteMstcpChan   chan *PacketBlock
	packetWriteAdapterChan chan *PacketBlock
}

// NewQueuedPacketFilter constructs a QueuedPacketFilter.
func NewQueuedPacketFilter(api *A.NdisApi, adapters *A.TcpAdapterList, in, out func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction) (*QueuedPacketFilter, error) {
	filter := &QueuedPacketFilter{
		NdisApi:  api,
		adapters: adapters,

		filterIncomingPacket: in,
		filterOutgoingPacket: out,
		filterState:          FilterStateStopped,
		adapter:              0,

		packetReadChan:         make(chan *PacketBlock, A.MaximumPacketBlock),
		packetProcessChan:      make(chan *PacketBlock, A.MaximumPacketBlock),
		packetWriteMstcpChan:   make(chan *PacketBlock, A.MaximumPacketBlock),
		packetWriteAdapterChan: make(chan *PacketBlock, A.MaximumPacketBlock),
	}

	err := filter.initializeNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	return filter, nil
}

// initFilter initializes the filter and associated data structures required for packet filtering.
func (f *QueuedPacketFilter) initFilter() error {
	for i := 0; i < A.MaximumBlockNum; i++ {
		packetBlock := NewPacketBlock(f.networkInterfaces[f.adapter].GetAdapter())
		f.packetReadChan <- packetBlock
	}

	// Set events for helper driver
	if err := f.networkInterfaces[f.adapter].SetPacketEvent(); err != nil {
		for len(f.packetReadChan) > 0 {
			<-f.packetReadChan
		}
		return err
	}

	f.networkInterfaces[f.adapter].SetMode(
		func() uint32 {
			mode := uint32(0)
			if f.filterOutgoingPacket != nil {
				mode |= A.MSTCP_FLAG_SENT_TUNNEL
			}
			if f.filterIncomingPacket != nil {
				mode |= A.MSTCP_FLAG_RECV_TUNNEL
			}
			return mode
		}(),
	)

	return nil
}

// Close releases the filter and associated data structures.
func (f *QueuedPacketFilter) Close() {
	f.networkInterfaces[f.adapter].Close()

	// Clear all queues
	for len(f.packetReadChan) > 0 {
		<-f.packetReadChan
	}

	for len(f.packetProcessChan) > 0 {
		<-f.packetProcessChan
	}

	for len(f.packetWriteMstcpChan) > 0 {
		<-f.packetWriteMstcpChan
	}

	for len(f.packetWriteAdapterChan) > 0 {
		<-f.packetWriteAdapterChan
	}
}

// Reconfigure updates available network interfaces. Should be called when the filter is inactive.
func (f *QueuedPacketFilter) Reconfigure() error {
	if f.filterState != FilterStateStopped {
		return errors.New("filter is not stopped")
	}

	f.networkInterfaces = make([]*N.NetworkAdapter, 0)
	if err := f.initializeNetworkInterfaces(); err != nil {
		return err
	}

	return nil
}

// StartFilter starts packet filtering.
func (f *QueuedPacketFilter) StartFilter(adapterIdx int) error {
	if f.filterState != FilterStateStopped {
		return errors.New("filter is not stopped")
	}

	f.filterState = FilterStateStarting
	f.adapter = adapterIdx

	if err := f.initFilter(); err != nil {
		f.filterState = FilterStateStopped
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.cancelFunc = cancel

	f.wg.Add(4)

	go f.packetRead(ctx)
	go f.packetProcess(ctx)
	go f.packetWriteMstcp(ctx)
	go f.packetWriteAdapter(ctx)

	f.filterState = FilterStateRunning

	return nil
}

// StopFilter stops packet filtering.
func (f *QueuedPacketFilter) StopFilter() error {
	if f.filterState != FilterStateRunning {
		return errors.New("filter is not running")
	}

	f.filterState = FilterStateStopping

	// Cancel the context to stop all goroutines
	if f.cancelFunc != nil {
		f.cancelFunc()
	}

	f.filterState = FilterStateStopped

	return nil
}

// initializeNetworkInterfaces initializes available network interface list.
func (f *QueuedPacketFilter) initializeNetworkInterfaces() error {
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

// InsertPacketToMstcp inserts a packet into the inbound network flow.
func (f *QueuedPacketFilter) InsertPacketToMstcp(packetData *A.IntermediateBuffer) error {
	request := &A.EtherRequest{
		AdapterHandle: f.networkInterfaces[f.adapter].GetAdapter(),
		EthernetPacket: A.EthernetPacket{
			Buffer: packetData,
		},
	}

	return f.SendPacketToMstcp(request)
}

// InsertPacketToAdapter inserts a packet into the outbound network flow.
func (f *QueuedPacketFilter) InsertPacketToAdapter(packetData *A.IntermediateBuffer) error {
	request := &A.EtherRequest{
		AdapterHandle: f.networkInterfaces[f.adapter].GetAdapter(),
		EthernetPacket: A.EthernetPacket{
			Buffer: packetData,
		},
	}

	return f.SendPacketToAdapter(request)
}

// packetRead reads packets from the network interface.
func (q *QueuedPacketFilter) packetRead(ctx context.Context) {
	defer q.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if q.filterState != FilterStateRunning {
				return
			}

			packetBlock := <-q.packetReadChan

			readRequest := packetBlock.GetReadRequest()

			for q.filterState == FilterStateRunning {
				_, err := q.networkInterfaces[q.adapter].WaitEvent(windows.INFINITE)
				if err != nil {
					ctx.Done()
					return
				}

				err = q.networkInterfaces[q.adapter].ResetEvent()
				if err != nil {
					ctx.Done()
					return
				}

				if !q.ReadPackets(readRequest) {
					break
				}
			}

			q.packetProcessChan <- packetBlock
		}
	}
}

// packetProcess processes the read packets.
func (q *QueuedPacketFilter) packetProcess(ctx context.Context) {
	defer q.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if q.filterState != FilterStateRunning {
				return
			}

			packetBlock := <-q.packetProcessChan

			readRequest := packetBlock.GetReadRequest()
			writeAdapterRequest := packetBlock.GetWriteAdapterRequest()
			writeMstcpRequest := packetBlock.GetWriteMstcpRequest()

			for i := 0; i < int(readRequest.PacketsSuccess); i++ {
				packetAction := A.FilterActionPass

				if packetBlock.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
					if q.filterOutgoingPacket != nil {
						packetAction = q.filterOutgoingPacket(readRequest.AdapterHandle, &packetBlock.packetBuffer[i])
					}
				} else {
					if q.filterIncomingPacket != nil {
						packetAction = q.filterIncomingPacket(readRequest.AdapterHandle, &packetBlock.packetBuffer[i])
					}
				}

				if packetAction == A.FilterActionPass {
					if packetBlock.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
						writeAdapterRequest.EthernetPackets[writeAdapterRequest.PacketsNumber].Buffer = &packetBlock.packetBuffer[i]
						writeAdapterRequest.PacketsNumber++
					} else {
						writeMstcpRequest.EthernetPackets[writeMstcpRequest.PacketsNumber].Buffer = &packetBlock.packetBuffer[i]
						writeMstcpRequest.PacketsNumber++
					}
				} else if packetAction == A.FilterActionRedirect {
					if packetBlock.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_RECEIVE {
						writeAdapterRequest.EthernetPackets[writeAdapterRequest.PacketsNumber].Buffer = &packetBlock.packetBuffer[i]
						writeAdapterRequest.PacketsNumber++
					} else {
						writeMstcpRequest.EthernetPackets[writeMstcpRequest.PacketsNumber].Buffer = &packetBlock.packetBuffer[i]
						writeMstcpRequest.PacketsNumber++
					}
				}
			}

			readRequest.PacketsSuccess = 0

			q.packetWriteMstcpChan <- packetBlock
		}
	}
}

// packetWriteMstcp writes packets to the MSTCP.
func (q *QueuedPacketFilter) packetWriteMstcp(ctx context.Context) {
	defer q.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if q.filterState != FilterStateRunning {
				return
			}

			packetBlock := <-q.packetWriteMstcpChan

			writeMstcpRequest := packetBlock.GetWriteMstcpRequest()
			if writeMstcpRequest.PacketsNumber > 0 {
				q.SendPacketsToMstcp(writeMstcpRequest)
				writeMstcpRequest.PacketsNumber = 0
			}

			q.packetWriteAdapterChan <- packetBlock
		}
	}
}

// packetWriteAdapter writes packets to the adapter.
func (q *QueuedPacketFilter) packetWriteAdapter(ctx context.Context) {
	defer q.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if q.filterState != FilterStateRunning {
				return
			}

			packetBlock := <-q.packetWriteAdapterChan

			writeAdapterRequest := packetBlock.GetWriteAdapterRequest()
			if writeAdapterRequest.PacketsNumber > 0 {
				q.SendPacketsToAdapter(writeAdapterRequest)
				writeAdapterRequest.PacketsNumber = 0
			}

			q.packetReadChan <- packetBlock
		}
	}
}

// GetFilterState returns the current filter state.
func (f *QueuedPacketFilter) GetFilterState() FilterState {
	return f.filterState
}
