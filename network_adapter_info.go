package ndisapi

import (
	"net"
	"sort"
)

type NetworkAdapterInfo struct {
	*net.Interface

	AdapterIndex  uint32
	AdapterHandle Handle
	AdapterMedium uint32
}

// GetNetworkAdapterInfo retrieves the combined network adapter information.
func GetNetworkAdapterInfo(api *NdisApi) ([]*NetworkAdapterInfo, *TcpAdapterList, error) {
	// Get TCPIP-bound adapters information
	tcpAdapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, nil, err
	}

	var adapterInfo []*NetworkAdapterInfo
	for i := range tcpAdapters.AdapterCount {
		adapterName := api.ConvertWindows2000AdapterName(string(tcpAdapters.AdapterNameList[i][:]))

		iface, err := net.InterfaceByName(adapterName)
		if iface == nil {
			continue
		}

		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip loopback interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Check if the interface has an IP address
		_, err = iface.Addrs()
		if err != nil {
			continue
		}

		adapterInfo = append(adapterInfo, &NetworkAdapterInfo{
			Interface: iface,

			AdapterIndex:  i,
			AdapterHandle: tcpAdapters.AdapterHandle[i],
			AdapterMedium: tcpAdapters.AdapterMediumList[i],
		})
	}

	// sort by default net.Interfaces order
	// usually it's sorted the best interfaces at top
	sort.Slice(adapterInfo, func(i, j int) bool {
		return adapterInfo[i].Index < adapterInfo[j].Index
	})

	return adapterInfo, tcpAdapters, nil
}
