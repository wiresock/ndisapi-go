//go:build windows

package driver

import (
	"fmt"
	"unsafe"

	A "github.com/wiresock/ndisapi-go"
)

type StaticFilters struct {
	*A.NdisApi
	Filters []Filter
}

// NewStaticFilter constructs a StaticFilter.
func NewStaticFilters(api *A.NdisApi, filterCache, fragmentCache bool) (*StaticFilters, error) {
	if !api.IsDriverLoaded() {
		return nil, fmt.Errorf("windows packet filter driver is not available")
	}

	staticFilter := &StaticFilters{
		NdisApi: api,
		Filters: []Filter{},
	}

	err := api.SetPacketFilterCacheState(filterCache)
	if err != nil {
		return nil, fmt.Errorf("SetPacketFilterCacheState: %v", err)
	}

	err = api.SetPacketFragmentCacheState(fragmentCache)
	if err != nil {
		return nil, fmt.Errorf("SetPacketFragmentCacheState: %v", err)
	}

	return staticFilter, nil
}

// Reset resets the filter table and re-initializes network interfaces.
func (f *StaticFilters) Close() {
	_ = f.ResetPacketFilterTable()
}

// AddFilterFront adds a filter to the front of the filter list.
func (f *StaticFilters) AddFilterFront(filter *Filter) bool {
	staticFilter := f.toStaticFilter(filter)
	if err := f.NdisApi.AddStaticFilterFront(staticFilter); err == nil {
		f.Filters = append([]Filter{*filter}, f.Filters...)
		return true
	}
	return false
}

// AddFilterBack adds a filter to the back of the filter list.
func (f *StaticFilters) AddFilterBack(filter *Filter) bool {
	staticFilter := f.toStaticFilter(filter)
	if err := f.NdisApi.AddStaticFilterBack(staticFilter); err == nil {
		f.Filters = append(f.Filters, *filter)
		return true
	}
	return false
}

// InsertFilter inserts a filter at the specified position in the filter list.
func (f *StaticFilters) InsertFilter(filter *Filter, position int) bool {
	if position > len(f.Filters) {
		return false
	}

	staticFilter := f.toStaticFilter(filter)
	if err := f.NdisApi.InsertStaticFilter(staticFilter, uint32(position)); err == nil {
		f.Filters = append(f.Filters[:position], append([]Filter{*filter}, f.Filters[position:]...)...)
		return true
	}
	return false
}

// RemoveFilter removes a filter at the specified position in the filter list.
func (f *StaticFilters) RemoveFilter(position int) bool {
	if position >= len(f.Filters) {
		return false
	}

	if err := f.NdisApi.RemoveStaticFilter(uint32(position)); err == nil {
		f.Filters = append(f.Filters[:position], f.Filters[position+1:]...)
		return true
	}
	return false
}

// RemoveFiltersIf removes filters from the list based on a predicate.
func (f *StaticFilters) RemoveFiltersIf(predicate func(*Filter) bool) {
	position := 0
	for it := 0; it < len(f.Filters); {
		if predicate(&f.Filters[it]) {
			if f.RemoveFilter(position) {
				f.Filters = append(f.Filters[:it], f.Filters[it+1:]...)
				// Do not increment position since we removed an element
			} else {
				// fmt.Printf("Failed to remove filter at position: %d\n", position)
				it++
				position++
			}
		} else {
			it++
			position++
		}
	}
}

// Contains checks if a filter is present in the list.
func (f *StaticFilters) Contains(filter *Filter) bool {
	for _, existingFilter := range f.Filters {
		if existingFilter.Equal(filter) {
			return true
		}
	}
	return false
}

// StoreTable stores the current filter table to the driver.
func (f *StaticFilters) StoreTable() error {
	filterSize := len(f.Filters)
	tableBuffer := make([]byte, int(unsafe.Sizeof(A.StaticFilterTable{}))+(filterSize)*int(unsafe.Sizeof(A.StaticFilter{})))
	table := (*A.StaticFilterTable)(unsafe.Pointer(&tableBuffer[0]))

	for i := range tableBuffer {
		tableBuffer[i] = 0
	}

	table.TableSize = uint32(filterSize)

	for i, filter := range f.Filters {
		table.StaticFilters[i] = *f.toStaticFilter(&filter)
	}

	if err := f.SetPacketFilterTable(table); err != nil {
		return fmt.Errorf("failed to store filter table: %v", err)
	}

	return nil
}

// LoadTable loads the filter table from the driver.
func (f *StaticFilters) LoadTable() (*A.StaticFilterTable, error) {
	var err error
	var tableSize uint32
	tableSize, err = f.GetPacketFilterTableSize()
	if err != nil || tableSize == 0 {
		// Failed to get table size or table is empty
		return nil, err
	}

	table, err := f.GetPacketFilterTable(tableSize)
	if err != nil {
		// Failed to get the filter table
		return nil, err
	}

	// Clear the current filters list
	f.Filters = []Filter{}

	// Iterate through the STATIC_FILTER entries and reconstruct the filters list
	for i := 0; i < int(tableSize); i++ { // Last entry is the default action, so we skip it
		staticFilter := table.StaticFilters[i]
		f.Filters = append(f.Filters, *f.fromStaticFilter(&staticFilter))
	}

	return table, nil
}

// toStaticFilter converts a Filter instance to a StaticFilterEntry.
func (f *StaticFilters) toStaticFilter(filter *Filter) *A.StaticFilter {
	var staticFilter A.StaticFilter
	staticFilter.Adapter = filter.AdapterHandle

	// Direction
	switch filter.Direction {
	case PacketDirectionIn:
		staticFilter.DirectionFlags = A.PACKET_FLAG_ON_RECEIVE
	case PacketDirectionOut:
		staticFilter.DirectionFlags = A.PACKET_FLAG_ON_SEND
	case PacketDirectionBoth:
		staticFilter.DirectionFlags = A.PACKET_FLAG_ON_SEND | A.PACKET_FLAG_ON_RECEIVE
	}

	// Action
	switch filter.Action {
	case A.FilterActionPass:
		staticFilter.FilterAction = A.FILTER_PACKET_PASS
	case A.FilterActionDrop:
		staticFilter.FilterAction = A.FILTER_PACKET_DROP
	case A.FilterActionRedirect:
		staticFilter.FilterAction = A.FILTER_PACKET_REDIRECT
	case A.FilterActionPassRedirect:
		staticFilter.FilterAction = A.FILTER_PACKET_PASS_RDR
	case A.FilterActionDropRedirect:
		staticFilter.FilterAction = A.FILTER_PACKET_DROP_RDR
	}

	// Data Link Layer
	if filter.SourceMacAddress != nil || filter.DestinationMacAddress != nil || filter.EthernetType > 0 {
		staticFilter.ValidFields |= A.DATA_LINK_LAYER_VALID
		staticFilter.DataLinkFilter.Selector = A.ETH_802_3

		if srcHWAddr := filter.SourceMacAddress; srcHWAddr != nil {
			staticFilter.DataLinkFilter.Eth8023Filter.ValidFields |= A.ETH_802_3_SRC_ADDRESS
			copy(staticFilter.DataLinkFilter.Eth8023Filter.SourceAddress[:], srcHWAddr)
		}

		if destHWAddr := filter.DestinationMacAddress; destHWAddr != nil {
			staticFilter.DataLinkFilter.Eth8023Filter.ValidFields |= A.ETH_802_3_DEST_ADDRESS
			copy(staticFilter.DataLinkFilter.Eth8023Filter.DestinationAddress[:], destHWAddr)
		}

		if ethernetType := filter.EthernetType; ethernetType > 0 {
			staticFilter.DataLinkFilter.Eth8023Filter.ValidFields |= A.ETH_802_3_PROTOCOL
			staticFilter.DataLinkFilter.Eth8023Filter.Protocol = ethernetType
		}
	}

	// Network Layer
	if filter.SourceAddress.IP != nil || filter.DestinationAddress.IP != nil || filter.Protocol > 0 {
		staticFilter.ValidFields |= A.NETWORK_LAYER_VALID
		if filter.SourceAddress.IP != nil {
			if filter.SourceAddress.IP.To4() != nil {
				staticFilter.NetworkFilter.Selector = A.IPV4
			} else {
				staticFilter.NetworkFilter.Selector = A.IPV6
			}
		}

		if srcAddr := filter.SourceAddress; srcAddr.IP != nil {
			if srcAddr.IP.To4() != nil {
				staticFilter.NetworkFilter.SetIPv4(A.IPv4Filter{
					ValidFields:   A.IP_V4_FILTER_SRC_ADDRESS,
					SourceAddress: *A.IPv4AddressFromIP(srcAddr),
				})
			} else {
				staticFilter.NetworkFilter.SetIPv6(A.IPv6Filter{
					ValidFields:   A.IP_V6_FILTER_SRC_ADDRESS,
					SourceAddress: *A.IPv6AddressFromIP(srcAddr),
				})
			}
		}

		if destAddr := filter.DestinationAddress; destAddr.IP != nil {
			if destAddr.IP.To4() != nil {
				staticFilter.NetworkFilter.SetIPv4(A.IPv4Filter{
					ValidFields:        A.IP_V4_FILTER_DEST_ADDRESS,
					DestinationAddress: *A.IPv4AddressFromIP(destAddr),
				})
			} else {
				staticFilter.NetworkFilter.SetIPv6(A.IPv6Filter{
					ValidFields:        A.IP_V6_FILTER_DEST_ADDRESS,
					DestinationAddress: *A.IPv6AddressFromIP(destAddr),
				})
			}
		}

		if protocol := filter.Protocol; protocol > 0 {
			if filter.SourceAddress.IP != nil {
				if filter.SourceAddress.IP.To4() != nil {
					staticFilter.NetworkFilter.SetIPv4(A.IPv4Filter{
						ValidFields: A.IP_V4_FILTER_PROTOCOL,
						Protocol:    protocol,
					})
				} else {
					staticFilter.NetworkFilter.SetIPv6(A.IPv6Filter{
						ValidFields: A.IP_V6_FILTER_PROTOCOL,
						Protocol:    protocol,
					})
				}
			}
		}
	}

	// Transport Layer
	if filter.SourcePort != [2]uint16{} || filter.DestinationPort != [2]uint16{} {
		staticFilter.ValidFields |= A.TRANSPORT_LAYER_VALID
		staticFilter.TransportFilter.Selector = A.TCPUDP

		if srcPort := filter.SourcePort; srcPort != [2]uint16{} {
			staticFilter.TransportFilter.SetTCPUDP(A.TCPUDPFilter{
				ValidFields: A.TCPUDP_SRC_PORT,
				SourcePort: A.PortRange{
					StartRange: srcPort[0],
					EndRange:   srcPort[1],
				},
			})
		}

		if destinationPort := filter.DestinationPort; destinationPort != [2]uint16{} {
			staticFilter.TransportFilter.SetTCPUDP(A.TCPUDPFilter{
				ValidFields: A.TCPUDP_DEST_PORT,
				DestinationPort: A.PortRange{
					StartRange: destinationPort[0],
					EndRange:   destinationPort[1],
				},
			})
		}
	}

	return &staticFilter
}

// fromStaticFilter converts a StaticFilterEntry to a Filter instance.
func (f *StaticFilters) fromStaticFilter(staticFilter *A.StaticFilter) *Filter {
	var filter Filter
	filter.AdapterHandle = staticFilter.Adapter

	// Direction
	if staticFilter.DirectionFlags&A.PACKET_FLAG_ON_RECEIVE != 0 {
		if staticFilter.DirectionFlags&A.PACKET_FLAG_ON_SEND != 0 {
			filter.Direction = PacketDirectionBoth
		} else {
			filter.Direction = PacketDirectionIn
		}
	} else if staticFilter.DirectionFlags&A.PACKET_FLAG_ON_SEND != 0 {
		filter.Direction = PacketDirectionOut
	}

	// Action
	switch staticFilter.FilterAction {
	case A.FILTER_PACKET_PASS:
		filter.Action = A.FilterActionPass
	case A.FILTER_PACKET_DROP:
		filter.Action = A.FilterActionDrop
	case A.FILTER_PACKET_REDIRECT:
		filter.Action = A.FilterActionRedirect
	case A.FILTER_PACKET_PASS_RDR:
		filter.Action = A.FilterActionPassRedirect
	case A.FILTER_PACKET_DROP_RDR:
		filter.Action = A.FilterActionDropRedirect
	}

	// Data Link Layer
	if staticFilter.ValidFields&A.DATA_LINK_LAYER_VALID != 0 {
		if staticFilter.DataLinkFilter.Selector == A.ETH_802_3 {
			if staticFilter.DataLinkFilter.Eth8023Filter.ValidFields&A.ETH_802_3_SRC_ADDRESS != 0 {
				filter.SourceMacAddress = staticFilter.DataLinkFilter.Eth8023Filter.SourceAddress[:]
			}
			if staticFilter.DataLinkFilter.Eth8023Filter.ValidFields&A.ETH_802_3_DEST_ADDRESS != 0 {
				filter.DestinationMacAddress = staticFilter.DataLinkFilter.Eth8023Filter.DestinationAddress[:]
			}
			if staticFilter.DataLinkFilter.Eth8023Filter.ValidFields&A.ETH_802_3_PROTOCOL != 0 {
				filter.EthernetType = staticFilter.DataLinkFilter.Eth8023Filter.Protocol
			}
		}
	}

	// Network Layer
	if staticFilter.ValidFields&A.NETWORK_LAYER_VALID != 0 {
		if staticFilter.NetworkFilter.Selector == A.IPV4 {
			if staticFilter.NetworkFilter.GetIPv4().ValidFields&A.IP_V4_FILTER_SRC_ADDRESS != 0 {
				filter.SourceAddress = A.IPv4AddressToIPNet(&staticFilter.NetworkFilter.GetIPv4().SourceAddress)
			}
			if staticFilter.NetworkFilter.GetIPv4().ValidFields&A.IP_V4_FILTER_DEST_ADDRESS != 0 {
				filter.DestinationAddress = A.IPv4AddressToIPNet(&staticFilter.NetworkFilter.GetIPv4().DestinationAddress)
			}
		} else if staticFilter.NetworkFilter.Selector == A.IPV6 {
			if staticFilter.NetworkFilter.GetIPv6().ValidFields&A.IP_V6_FILTER_SRC_ADDRESS != 0 {
				filter.SourceAddress = A.IPv6AddressToIPNet(&staticFilter.NetworkFilter.GetIPv6().SourceAddress)
			}
			if staticFilter.NetworkFilter.GetIPv6().ValidFields&A.IP_V6_FILTER_DEST_ADDRESS != 0 {
				filter.DestinationAddress = A.IPv6AddressToIPNet(&staticFilter.NetworkFilter.GetIPv6().DestinationAddress)
			}
		}
		if staticFilter.NetworkFilter.Selector == A.IPV4 && staticFilter.NetworkFilter.GetIPv4().ValidFields&A.IP_V4_FILTER_PROTOCOL != 0 {
			filter.Protocol = staticFilter.NetworkFilter.GetIPv4().Protocol
		} else if staticFilter.NetworkFilter.Selector == A.IPV6 && staticFilter.NetworkFilter.GetIPv6().ValidFields&A.IP_V6_FILTER_PROTOCOL != 0 {
			filter.Protocol = staticFilter.NetworkFilter.GetIPv6().Protocol
		}
	}

	// Transport Layer
	if staticFilter.ValidFields&A.TRANSPORT_LAYER_VALID != 0 {
		if staticFilter.TransportFilter.Selector == A.TCPUDP {
			if staticFilter.TransportFilter.GetTCPUDP().ValidFields&A.TCPUDP_SRC_PORT != 0 {
				filter.SourcePort = [2]uint16{staticFilter.TransportFilter.GetTCPUDP().SourcePort.StartRange, staticFilter.TransportFilter.GetTCPUDP().SourcePort.EndRange}
			}
			if staticFilter.TransportFilter.GetTCPUDP().ValidFields&A.TCPUDP_DEST_PORT != 0 {
				filter.DestinationPort = [2]uint16{staticFilter.TransportFilter.GetTCPUDP().DestinationPort.StartRange, staticFilter.TransportFilter.GetTCPUDP().DestinationPort.EndRange}
			}
		}
	}
	filter.StaticFilter = staticFilter
	return &filter
}
