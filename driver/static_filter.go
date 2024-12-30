//go:build windows

package driver

import (
	"sync"
	"syscall"
	"unsafe"

	A "github.com/wiresock/ndisapi-go"
	N "github.com/wiresock/ndisapi-go/netlib"
)

type StaticFilter struct {
	*A.NdisApi

	defaultAction     A.FilterAction
	networkInterfaces []*N.NetworkAdapter

	filters []*Filter
}

// singleton StaticFilter
var instance *StaticFilter
var once sync.Once

// GetStaticFilter returns a singleton instance of StaticFilter with the provided NdisApi and default actio
// It initializes network interfaces if not already initialized.
func GetStaticFilter(api *A.NdisApi, action A.FilterAction) (*StaticFilter, error) {
	once.Do(func() {
		instance = &StaticFilter{
			NdisApi: api,

			defaultAction:     action,
			networkInterfaces: make([]*N.NetworkAdapter, 0),

			filters: []*Filter{},
		}
	})

	err := instance.initializeNetworkInterfaces()
	if err != nil {
		return nil, nil
	}

	return instance, nil
}

// AddFilter adds a new filter to the StaticFilter instance.
func (f *StaticFilter) AddFilter(filter *Filter) *StaticFilter {
	f.filters = append(f.filters, filter)
	return f
}

// Apply applies the configured filters to the network interfaces.
func (f *StaticFilter) Apply() error {
	// Allocate table filters
	tableBuffer := make([]byte, int(unsafe.Sizeof(A.StaticFilterTable{}))+(len(f.filters))*int(unsafe.Sizeof(A.StaticFilterEntry{})))
	filterList := (*A.StaticFilterTable)(unsafe.Pointer(&tableBuffer[0]))

	for i := range tableBuffer {
		tableBuffer[i] = 0
	}

	// Set table size
	filterList.StaticFilters = make([]A.StaticFilterEntry, len(f.filters)+1)
	filterList.TableSize = uint32(len(f.filters) + 1)

	// Populate the filter list
	for i, filter := range f.filters {
		f.toStaticFilter(filter, &filterList.StaticFilters[i])
	}

	// Set the default rule
	defaultFilter := &filterList.StaticFilters[len(f.filters)]
	defaultFilter.Adapter = A.Handle{0, 0, 0, 0, 0, 0, 0, 0}
	defaultFilter.ValidFields = 0

	switch f.defaultAction {
	case A.FilterActionPass:
		defaultFilter.FilterAction = FILTER_PACKET_PASS
	case A.FilterActionDrop:
		defaultFilter.FilterAction = FILTER_PACKET_DROP
	case A.FilterActionRedirect:
		defaultFilter.FilterAction = FILTER_PACKET_REDIRECT
	case A.FilterActionPassRedirect:
		defaultFilter.FilterAction = FILTER_PACKET_PASS_RDR
	case A.FilterActionDropRedirect:
		defaultFilter.FilterAction = FILTER_PACKET_DROP_RDR
	}
	defaultFilter.DirectionFlags = A.PACKET_FLAG_ON_RECEIVE | A.PACKET_FLAG_ON_SEND

	if err := f.SetPacketFilterTable(filterList); err != nil {
		return err
	}

	return nil
}

// Reset resets the filter table and re-initializes network interfaces.
func (f *StaticFilter) Reset() {
	_ = f.SetPacketFilterTable(nil)
	f.networkInterfaces = nil
	_ = f.initializeNetworkInterfaces()
}

// initializeNetworkInterfaces initializes the network interfaces bound to TCP/IP.
func (f *StaticFilter) initializeNetworkInterfaces() error {
	adapters, err := f.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return err
	}

	for i := 0; i < int(adapters.AdapterCount); i++ {
		name := string(adapters.AdapterNameList[i][:])
		adapterHandle := adapters.AdapterHandle[i]
		currentAddress := adapters.CurrentAddress[i]
		medium := adapters.AdapterMediumList[i]
		mtu := adapters.MTU[i]

		friendlyName := f.ConvertWindows2000AdapterName(name)

		networkAdapter, err := N.NewNetworkAdapter(f.NdisApi, adapterHandle, currentAddress, name, friendlyName, medium, mtu)
		if err != nil {
			continue
		}
		f.networkInterfaces = append(f.networkInterfaces, networkAdapter)
	}

	return nil
}

// toStaticFilter converts a Filter instance to a StaticFilterEntry.
func (f *StaticFilter) toStaticFilter(filter *Filter, staticFilter *A.StaticFilterEntry) {
	if index := filter.GetNetworkInterfaceIndex(); index != nil {
		staticFilter.Adapter = f.networkInterfaces[*index].GetAdapter()
	} else {
		staticFilter.Adapter = A.Handle{}
	}

	switch filter.GetDirection() {
	case PacketDirectionIn:
		staticFilter.DirectionFlags = A.PACKET_FLAG_ON_RECEIVE
	case PacketDirectionOut:
		staticFilter.DirectionFlags = A.PACKET_FLAG_ON_SEND
	case PacketDirectionBoth:
		staticFilter.DirectionFlags = A.PACKET_FLAG_ON_SEND | A.PACKET_FLAG_ON_RECEIVE
	}

	switch filter.GetAction() {
	case A.FilterActionPass:
		staticFilter.FilterAction = FILTER_PACKET_PASS
	case A.FilterActionDrop:
		staticFilter.FilterAction = FILTER_PACKET_DROP
	case A.FilterActionRedirect:
		staticFilter.FilterAction = FILTER_PACKET_REDIRECT
	case A.FilterActionPassRedirect:
		staticFilter.FilterAction = FILTER_PACKET_PASS_RDR
	case A.FilterActionDropRedirect:
		staticFilter.FilterAction = FILTER_PACKET_DROP_RDR
	}

	if filter.GetSourceHWAddress() != nil || filter.GetDestHWAddress() != nil || filter.GetEtherType() != nil {
		staticFilter.ValidFields |= DATA_LINK_LAYER_VALID
		staticFilter.DataLinkFilter.UnionSelector = ETH_802_3

		if srcHWAddr := filter.GetSourceHWAddress(); srcHWAddr != nil {
			staticFilter.DataLinkFilter.Eth8023Filter.ValidFields |= ETH_802_3_SRC_ADDRESS
			staticFilter.DataLinkFilter.Eth8023Filter.SrcAddress = *srcHWAddr
		}

		if destHWAddr := filter.GetDestHWAddress(); destHWAddr != nil {
			staticFilter.DataLinkFilter.Eth8023Filter.ValidFields |= ETH_802_3_DEST_ADDRESS
			staticFilter.DataLinkFilter.Eth8023Filter.DestAddress = *destHWAddr
		}

		if etherType := filter.GetEtherType(); etherType != nil {
			staticFilter.DataLinkFilter.Eth8023Filter.ValidFields |= ETH_802_3_PROTOCOL
			staticFilter.DataLinkFilter.Eth8023Filter.Protocol = *etherType
		}
	}

	if filter.GetSourceAddress() != nil || filter.GetDestAddress() != nil || filter.GetProtocol() != nil {
		staticFilter.ValidFields |= NETWORK_LAYER_VALID
		staticFilter.NetworkFilter.UnionSelector = IPV4

		if srcAddr := filter.GetSourceAddress(); srcAddr != nil {
			staticFilter.NetworkFilter.IPv4.ValidFields |= IP_V4_FILTER_SRC_ADDRESS
			staticFilter.NetworkFilter.IPv4.SrcAddress = A.IPv4AddressFromIP(*srcAddr)
		}

		if destAddr := filter.GetDestAddress(); destAddr != nil {
			staticFilter.NetworkFilter.IPv4.ValidFields |= IP_V4_FILTER_DEST_ADDRESS
			staticFilter.NetworkFilter.IPv4.DestAddress = A.IPv4AddressFromIP(*destAddr)
		}

		if protocol := filter.GetProtocol(); protocol != nil {
			staticFilter.NetworkFilter.IPv4.ValidFields |= IP_V4_FILTER_PROTOCOL
			staticFilter.NetworkFilter.IPv4.Protocol = *protocol
		}
	}

	if filter.GetSourcePort() != nil || filter.GetDestPort() != nil {
		staticFilter.ValidFields |= TRANSPORT_LAYER_VALID
		if protocol := filter.GetProtocol(); protocol != nil {
			if *protocol == syscall.IPPROTO_TCP || *protocol == syscall.IPPROTO_UDP {
				staticFilter.TransportFilter.UnionSelector = TCPUDP
			}
		}

		if srcPort := filter.GetSourcePort(); srcPort != nil {
			staticFilter.TransportFilter.TCPUDP.ValidFields |= TCPUDP_SRC_PORT
			staticFilter.TransportFilter.TCPUDP.SourcePort = A.PortRange{
				StartRange: srcPort[0],
				EndRange:   srcPort[1],
			}
		}

		if destPort := filter.GetDestPort(); destPort != nil {
			staticFilter.TransportFilter.TCPUDP.ValidFields |= TCPUDP_DEST_PORT
			staticFilter.TransportFilter.TCPUDP.DestPort = A.PortRange{
				StartRange: destPort[0],
				EndRange:   destPort[1],
			}
		}
	}
}
