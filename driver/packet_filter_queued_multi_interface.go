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

var _ PacketFilter = (*QueuedMultiInterfacePacketFilter)(nil)
var _ MultiInterfacePacketFilter = (*QueuedMultiInterfacePacketFilter)(nil)

// PacketFilterFunc defines the function signature for packet filtering.
type PacketFilterFunc func(handle A.Handle, buffer *A.IntermediateBuffer) (A.FilterAction, *A.Handle)

type QueuedMultiInterfacePacketFilter struct {
	*A.NdisApi
	sync.Mutex
	ctx context.Context

	adapters *A.TcpAdapterList

	filterIncomingPacket PacketFilterFunc
	filterOutgoingPacket PacketFilterFunc
	filterState          FilterState
	networkInterfaces    []*N.NetworkAdapter
	filterAdapterList    []string

	wg     sync.WaitGroup
	cancel context.CancelFunc

	packetReadChan         chan *UnsortedPacketBlock
	packetProcessChan      chan *UnsortedPacketBlock
	packetWriteMstcpChan   chan *UnsortedPacketBlock
	packetWriteAdapterChan chan *UnsortedPacketBlock

	adapterEvent *A.SafeEvent
	packetEvent  *A.SafeEvent
}

// NewQueuedMultiInterfacePacketFilter constructs a QueuedMultiInterfacePacketFilter.
func NewQueuedMultiInterfacePacketFilter(ctx context.Context, api *A.NdisApi, adapters *A.TcpAdapterList, in, out PacketFilterFunc) (*QueuedMultiInterfacePacketFilter, error) {
	filter := &QueuedMultiInterfacePacketFilter{
		ctx:      ctx,
		NdisApi:  api,
		adapters: adapters,

		filterIncomingPacket: in,
		filterOutgoingPacket: out,
		filterState:          FilterStateStopped,

		packetReadChan:         make(chan *UnsortedPacketBlock, A.UnsortedMaximumPacketBlock),
		packetProcessChan:      make(chan *UnsortedPacketBlock, A.UnsortedMaximumPacketBlock),
		packetWriteMstcpChan:   make(chan *UnsortedPacketBlock, A.UnsortedMaximumPacketBlock),
		packetWriteAdapterChan: make(chan *UnsortedPacketBlock, A.UnsortedMaximumPacketBlock),
	}

	adapterEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating event for adapter: %s", err.Error())
	}
	filter.adapterEvent = A.NewSafeEvent(adapterEvent)

	packetEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating event for adapter: %s", err.Error())
	}
	filter.packetEvent = A.NewSafeEvent(packetEvent)

	go filter.monitorAdapterChanges()
	if err := filter.SetAdapterListChangeEvent(adapterEvent); err != nil {
		return nil, err
	}

	err = filter.initializeNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	return filter, nil
}

// UpdateAdaptersFilterState updates the filter state of network adapters.
func (f *QueuedMultiInterfacePacketFilter) UpdateAdaptersFilterState() {
	for _, adapter := range f.networkInterfaces {
		matched := false
		if f.filterState == FilterStateRunning {
			for _, element := range f.filterAdapterList {
				if element == adapter.InternalName {
					mode := uint32(0)
					if f.filterOutgoingPacket != nil {
						mode |= A.MSTCP_FLAG_SENT_TUNNEL
					}
					if f.filterIncomingPacket != nil {
						mode |= A.MSTCP_FLAG_RECV_TUNNEL
					}
					adapter.SetMode(mode)
					adapter.SetPacketEvent()
					matched = true
					break
				}
			}
		}
		if !matched {
			adapter.ResetPacketEvent()
			adapter.SetMode(0)
		}
	}
}

// initFilter initializes the filter and associated data structures required for packet filtering.
func (f *QueuedMultiInterfacePacketFilter) initFilter() {
	for i := 0; i < A.UnsortedMaximumBlockNum; i++ {
		packetBlock := NewUnsortedPacketBlock()
		f.packetReadChan <- packetBlock
	}
}

// monitorAdapterChanges monitors network adapter changes.
func (f *QueuedMultiInterfacePacketFilter) monitorAdapterChanges() {
	for {
		select {
		case <-f.ctx.Done():
			return
		default:
			f.adapterEvent.Wait(windows.INFINITE)
			f.adapterEvent.Reset()
			if f.ctx.Err() == nil {
				f.onNetworkAdapterChange()
			}
		}
	}
}

// onNetworkAdapterChange handles network adapter changes.
func (f *QueuedMultiInterfacePacketFilter) onNetworkAdapterChange() {
	f.Lock()
	defer f.Unlock()

	f.networkInterfaces = nil

	if err := f.initializeNetworkInterfaces(); err != nil {
		fmt.Println("error initializing network interfaces:", err)
		return
	}

	f.UpdateAdaptersFilterState()
}

// FilterNetworkAdapter adds the specified network adapter to the filter list.
func (f *QueuedMultiInterfacePacketFilter) FilterNetworkAdapter(name string) {
	f.Lock()
	defer f.Unlock()
	f.filterAdapterList = append(f.filterAdapterList, name)
	f.UpdateAdaptersFilterState()
}

// UnfilterNetworkAdapter removes the specified network adapter from the filter list.
func (f *QueuedMultiInterfacePacketFilter) UnfilterNetworkAdapter(name string) {
	f.Lock()
	defer f.Unlock()
	for i, adapter := range f.filterAdapterList {
		if adapter == name {
			f.filterAdapterList = append(f.filterAdapterList[:i], f.filterAdapterList[i+1:]...)
			break
		}
	}
	f.UpdateAdaptersFilterState()
}

// GetFilteredAdapters retrieves a list of currently filtered network adapters.
func (f *QueuedMultiInterfacePacketFilter) GetFilteredAdapters() []string {
	f.Lock()
	defer f.Unlock()
	return append([]string(nil), f.filterAdapterList...)
}

// Reconfigure updates available network interfaces. Should be called when the filter is inactive.
func (f *QueuedMultiInterfacePacketFilter) Reconfigure() error {
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
func (f *QueuedMultiInterfacePacketFilter) StartFilter() error {
	if f.filterState != FilterStateStopped {
		return errors.New("filter is not stopped")
	}

	f.filterState = FilterStateStarting

	f.Lock()
	if len(f.filterAdapterList) == 0 {
		for _, adapter := range f.networkInterfaces {
			f.filterAdapterList = append(f.filterAdapterList, adapter.InternalName)
		}
	}

	f.filterState = FilterStateRunning
	f.initFilter()

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel

	f.wg.Add(4)
	go f.packetRead(ctx)
	go f.packetProcess(ctx)
	go f.packetWriteMstcp(ctx)
	go f.packetWriteAdapter(ctx)

	f.UpdateAdaptersFilterState()

	return nil
}

// StopFilter stops packet filtering.
func (f *QueuedMultiInterfacePacketFilter) Close() error {
	if f.filterState != FilterStateRunning {
		return errors.New("filter is not running")
	}

	f.filterState = FilterStateStopping
	f.adapterEvent.Signal()
	f.Lock()
	for _, adapter := range f.networkInterfaces {
		adapter.Close()
	}
	f.Unlock()
	f.cancel()
	// clear queues
	{
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
	f.wg.Wait()
	f.filterState = FilterStateStopped
	return nil
}

// initializeNetworkInterfaces initializes available network interface list.
func (f *QueuedMultiInterfacePacketFilter) initializeNetworkInterfaces() error {
	for i := 0; i < int(f.adapters.AdapterCount); i++ {
		name := string(f.adapters.AdapterNameList[i][:])
		adapterHandle := f.adapters.AdapterHandle[i]
		currentAddress := f.adapters.CurrentAddress[i]
		medium := f.adapters.AdapterMediumList[i]
		mtu := f.adapters.MTU[i]

		friendlyName := f.ConvertWindows2000AdapterName(name)

		networkAdapter, err := N.NewNetworkAdapter(f.NdisApi, adapterHandle, currentAddress, name, friendlyName, medium, mtu, f.packetEvent.Get())
		if err != nil {
			fmt.Println("error creating network adapter", err.Error())
			continue
		}
		f.networkInterfaces = append(f.networkInterfaces, networkAdapter)
	}

	return nil
}

// packetRead reads packets from the network interface.
func (q *QueuedMultiInterfacePacketFilter) packetRead(ctx context.Context) {
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
				_, err := q.packetEvent.Wait(windows.INFINITE)
				if err != nil {
					ctx.Done()
					return
				}

				err = q.packetEvent.Reset()
				if err != nil {
					ctx.Done()
					return
				}

				if q.ReadPacketsUnsorted(readRequest, uint32(len(readRequest)), &packetBlock.packetsSuccess) && packetBlock.packetsSuccess > 0 {
					break
				}
			}

			q.packetProcessChan <- packetBlock
		}
	}
}

// packetProcess processes the read packets.
func (q *QueuedMultiInterfacePacketFilter) packetProcess(ctx context.Context) {
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

			writeAdapterRequest := packetBlock.GetWriteAdapterRequest()
			writeMstcpRequest := packetBlock.GetWriteMstcpRequest()

			for i := 0; i < int(packetBlock.GetPacketsSuccess()); i++ {
				var adapterHandle *A.Handle
				packetAction := A.FilterActionPass

				if packetBlock.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
					if q.filterOutgoingPacket != nil {
						packetAction, adapterHandle = q.filterOutgoingPacket(packetBlock.packetBuffer[i].HAdapterQLinkUnion.GetAdapter(), &packetBlock.packetBuffer[i])
					}
				} else {
					if q.filterIncomingPacket != nil {
						packetAction, adapterHandle = q.filterIncomingPacket(packetBlock.packetBuffer[i].HAdapterQLinkUnion.GetAdapter(), &packetBlock.packetBuffer[i])
					}
				}

				if adapterHandle != nil {
					packetBlock.packetBuffer[i].HAdapterQLinkUnion.SetAdapter(*adapterHandle)
				}

				if packetAction == A.FilterActionPass {
					if packetBlock.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_SEND {
						packetBlock.SetWriteAdapterRequest(append(writeAdapterRequest, &packetBlock.packetBuffer[i]))
					} else {
						packetBlock.SetWriteMstcpRequest(append(writeMstcpRequest, &packetBlock.packetBuffer[i]))
					}
				} else if packetAction == A.FilterActionRedirect {
					if packetBlock.packetBuffer[i].DeviceFlags == A.PACKET_FLAG_ON_RECEIVE {
						packetBlock.SetWriteAdapterRequest(append(writeAdapterRequest, &packetBlock.packetBuffer[i]))
					} else {
						packetBlock.SetWriteMstcpRequest(append(writeMstcpRequest, &packetBlock.packetBuffer[i]))
					}
				}
			}

			q.packetWriteMstcpChan <- packetBlock
		}
	}
}

// packetWriteMstcp writes packets to the MSTCP.
func (q *QueuedMultiInterfacePacketFilter) packetWriteMstcp(ctx context.Context) {
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
			if len(writeMstcpRequest) > 0 {
				var packetsSent uint32
				q.SendPacketsToMstcpUnsorted(writeMstcpRequest, uint32(len(writeMstcpRequest)), &packetsSent)
				packetBlock.ClearWriteMstcpRequest()
			}

			q.packetWriteAdapterChan <- packetBlock
		}
	}
}

// packetWriteAdapter writes packets to the adapter.
func (q *QueuedMultiInterfacePacketFilter) packetWriteAdapter(ctx context.Context) {
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
			if len(writeAdapterRequest) > 0 {
				var packetsSent uint32
				q.SendPacketsToAdaptersUnsorted(writeAdapterRequest, uint32(len(writeAdapterRequest)), &packetsSent)
				packetBlock.ClearWriteAdapterRequest()
			}

			q.packetReadChan <- packetBlock
		}
	}
}

// GetFilterState returns the current filter state.
func (f *QueuedMultiInterfacePacketFilter) GetFilterState() FilterState {
	return f.filterState
}

// GetInterfaceList retrieves the list of all network interfaces available for packet filtering.
func (f *QueuedMultiInterfacePacketFilter) GetInterfaceList() []*N.NetworkAdapter {
	f.Lock()
	defer f.Unlock()
	return f.networkInterfaces
}
