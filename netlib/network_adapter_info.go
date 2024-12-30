package netlib

import (
	"fmt"
	"net"
	"sort"
	"syscall"

	A "github.com/wiresock/ndisapi-go"
)

type NetworkAdapterInfo struct {
	*net.Interface

	AdapterIndex  int
	AdapterHandle A.Handle
	AdapterMedium uint32
}

// GetNetworkAdapterInfo retrieves the combined network adapter information.
func GetNetworkAdapterInfo(api *A.NdisApi) ([]*NetworkAdapterInfo, *A.TcpAdapterList, error) {
	// Get TCPIP-bound adapters information
	tcpAdapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, nil, err
	}

	var adapterInfo []*NetworkAdapterInfo
	for i := 0; i < int(tcpAdapters.AdapterCount); i++ {
		adapterName := api.ConvertWindows2000AdapterName(string(tcpAdapters.AdapterNameList[i][:]))

		iface, _ := net.InterfaceByName(adapterName)
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

// GetBestInterface determines the best network interface for a given IP address.
// It uses a list of network adapter information to find the matching adapter.
func GetBestInterface(adapters []*NetworkAdapterInfo, ipStr string) (*NetworkAdapterInfo, error) {
	var bestIfIndex uint32 = 0

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}


	sockAddr, err := getAddrFromIPPort(ip.To4(), 0)
	if err != nil {
		return nil, err
	}

	err = getBestInterfaceEx(sockAddr, &bestIfIndex)
	if err != nil && bestIfIndex == 0 {
		return nil, err
	}

	for _, adapterInfo := range adapters {
		if adapterInfo.Index == int(bestIfIndex) {
			return adapterInfo, nil
		}
	}

	return nil, fmt.Errorf("IPv6 is not supported yet")
}

func getAddrFromIPPort(ip net.IP, port int) ([]byte, error) {
	if port < 0 || port > 0xFFFF {
		return nil, fmt.Errorf("port out of range (0-65535)")
	}

	var ipLen, ipOffset int
	var ipBytes []byte
	data := make([]byte, 64)

	if v4 := ip.To4(); v4 != nil {
		// IPv4
		data[0] = byte(syscall.AF_INET)       // Family
		data[1] = byte(syscall.AF_INET >> 8) // Upper byte of family
		ipLen = net.IPv4len
		ipOffset = 2
		ipBytes = v4
	} else {
		// IPv6
		data[0] = byte(syscall.AF_INET6)       // Family
		data[1] = byte(syscall.AF_INET6 >> 8) // Upper byte of family
		ipLen = net.IPv6len
		ipOffset = 6
		ipBytes = ip.To16()
	}

	if ipLen == 0 {
		return nil, fmt.Errorf("invalid IP")
	}

	// Add port in big-endian format
	bePort := uint16((port&0xFF)<<8 | (port>>8)&0xFF) // Equivalent to htons
	data[2] = byte(bePort >> 8) // High byte
	data[3] = byte(bePort & 0xFF) // Low byte

	// Copy the IP address into the data buffer
	copy(data[ipOffset:], ipBytes)

	return data, nil
}