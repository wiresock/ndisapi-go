//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"

	"github.com/wzshiming/socks5"

	"golang.org/x/sys/windows"
)

// TCPPortMapping stores the destination ip/port and transparent proxy port.
type TCPPortMapping struct {
	DstIP     net.IP
	DstPort   layers.TCPPort
	ProxyPort uint16
}
type UDPPortMapping struct {
	DstIP     net.IP
	DstPort   layers.UDPPort
	ProxyPort uint16
}

// SocksLocalRouter handles the routing of SOCKS traffic locally.
type SocksLocalRouter struct {
	sync.Mutex
	*A.NdisApi // API instance for interacting with the NDIS API.

	tcpConnections map[string]TCPPortMapping // Map to store TCP port mappings.
	udpEndpoints   map[string]UDPPortMapping // Map to store UDP port mappings.

	tcpMutex sync.RWMutex // Mutex for TCP map
	udpMutex sync.RWMutex // Mutex for UDP map

	ctx    context.Context // Context and cancel function for managing the router's lifecycle.
	cancel context.CancelFunc
	wg     sync.WaitGroup // WaitGroup to manage goroutines.

	proxyServers []*TransparentProxy // List of proxy servers managed by this router.
	nameToProxy  map[string]int      // Map to associate process names with proxy indices.

	ifNotifyHandle windows.Handle
	ifIndex        int // Index of the network interface used.
	adapters       *A.TcpAdapterList
	defaultAdapter *N.NetworkAdapterInfo

	processLookup *N.ProcessLookup // Process lookup instance.

	filter       *D.QueuedPacketFilter // Packet filter instance.
	staticFilter *D.StaticFilter       // Static filter instance.

	isActive bool // Boolean to track the active status of the router.
}

// NewSocksLocalRouter creates a new instance of SocksLocalRouter.
func NewSocksLocalRouter(api *A.NdisApi, debug bool) (*SocksLocalRouter, error) {
	// Get adapter information
	adapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, err
	}

	// Create context with cancel function
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize SocksLocalRouter
	socksLocalRouter := &SocksLocalRouter{
		NdisApi: api,

		ctx:    ctx,
		cancel: cancel,

		nameToProxy: make(map[string]int),

		tcpConnections: make(map[string]TCPPortMapping),
		udpEndpoints:   make(map[string]UDPPortMapping),

		processLookup: &N.ProcessLookup{},

		adapters: adapters,

		isActive: false,
	}

	// Create packet filter
	filter, err := D.NewQueuedPacketFilter(api, socksLocalRouter.adapters, nil, func(handle A.Handle, b *A.IntermediateBuffer) A.FilterAction {
		packet := gopacket.NewPacket(b.Buffer[:], layers.LayerTypeEthernet, gopacket.Default)

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			return A.FilterActionPass
		}
		ethernet := ethernetLayer.(*layers.Ethernet)
		if ethernet.EthernetType != layers.EthernetTypeIPv4 && ethernet.EthernetType != layers.EthernetTypeIPv6 {
			return A.FilterActionPass
		}

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)

		if ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)

			switch ip.Protocol {
			case layers.IPProtocolTCP:
				tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.SrcIP)), uint16(tcp.SrcPort))
				dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.DstPort))

				var proxyPort uint16
				var redirected bool = false
				if tcp.SYN && !tcp.ACK {
					processInfo, err := socksLocalRouter.processLookup.FindProcessInfo(ctx, false, src, dst, false)
					if err == nil {
						proxyPort = socksLocalRouter.GetProxyPortTCP(processInfo)
						if proxyPort != 0 {
							log.Printf("[TCP] %s - %s -> %s (Redirected)", filepath.Base(processInfo.PathName), src.String(), dst.String())

							connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.SrcPort)).String()

							socksLocalRouter.tcpMutex.Lock()
							if _, loaded := socksLocalRouter.tcpConnections[connName]; loaded {
								redirected = true
							} else {
								socksLocalRouter.tcpConnections[connName] = TCPPortMapping{
									DstIP:     ip.DstIP,
									DstPort:   tcp.DstPort,
									ProxyPort: proxyPort,
								}
								redirected = true
							}
							socksLocalRouter.tcpMutex.Unlock()
						}
					}
				} else {
					connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.SrcPort)).String()

					socksLocalRouter.tcpMutex.RLock()
					it, exists := socksLocalRouter.tcpConnections[connName]
					socksLocalRouter.tcpMutex.RUnlock()
					if exists {
						if tcp.RST || tcp.FIN {
							socksLocalRouter.tcpMutex.Lock()
							delete(socksLocalRouter.tcpConnections, connName)
							socksLocalRouter.tcpMutex.Unlock()

							log.Printf("[TCP] %s - %s (Closed)", src.String(), dst.String())
						}

						redirected = true
						proxyPort = it.ProxyPort
					}
				}

				if redirected {
					// Swap Ethernet addresses
					ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
					// Swap IP addresses
					ip.DstIP, ip.SrcIP = ip.SrcIP, ip.DstIP
					// Change destination port to the transparent proxy
					tcp.DstPort = layers.TCPPort(proxyPort)
					// Compute checksums & serialize the packet
					tcp.SetNetworkLayerForChecksum(ip)
					serializePacket(b, packet)

					return A.FilterActionRedirect
				} else if socksLocalRouter.IsTCPProxyPort(tcp.SrcPort) {
					connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.DstPort)).String()

					socksLocalRouter.tcpMutex.Lock()
					it, exists := socksLocalRouter.tcpConnections[connName]
					if !exists {
						socksLocalRouter.tcpMutex.Unlock()
						return A.FilterActionPass
					}

					if tcp.RST || tcp.FIN {
						delete(socksLocalRouter.tcpConnections, connName)
						log.Printf("[TCP] %s - %s (Closed)", src.String(), dst.String())
					}
					socksLocalRouter.tcpMutex.Unlock()

					// Redirect the packet back to the original destination
					tcp.SrcPort = layers.TCPPort(it.DstPort)
					// Swap Ethernet addresses
					ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
					// Swap IP addresses
					ip.DstIP, ip.SrcIP = ip.SrcIP, ip.DstIP
					// Compute checksums & serialize the packet
					tcp.SetNetworkLayerForChecksum(ip)
					serializePacket(b, packet)

					return A.FilterActionRedirect
				}
				break
			case layers.IPProtocolUDP:
				udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

				src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.SrcIP)), uint16(udp.SrcPort))
				dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(udp.DstPort))

				// Skip broadcast and multicast UDP packets
				if ip.DstIP.IsMulticast() || ip.DstIP.Equal(net.IPv4bcast) {
					return A.FilterActionPass
				}

				var proxyPort uint16
				var redirected bool = false

				endpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(udp.SrcPort)).String()
				socksLocalRouter.udpMutex.RLock()
				it, exists := socksLocalRouter.udpEndpoints[endpoint]
				socksLocalRouter.udpMutex.RUnlock()

				// Check if this is a new endpoint
				if !exists {
					processInfo, err := socksLocalRouter.processLookup.FindProcessInfo(ctx, true, src, dst, false)
					if err != nil {
						return A.FilterActionPass
					}

					proxyPort = socksLocalRouter.GetProxyPortUDP(processInfo)
					if proxyPort != 0 {
						log.Printf("[UDP] %s - %s -> %s", filepath.Base(processInfo.PathName), src.String(), dst.String())

						socksLocalRouter.udpMutex.Lock()
						if _, loaded := socksLocalRouter.udpEndpoints[endpoint]; !loaded {
							socksLocalRouter.udpEndpoints[endpoint] = UDPPortMapping{
								DstIP:     ip.DstIP,
								DstPort:   udp.DstPort,
								ProxyPort: proxyPort,
							}
						}
						socksLocalRouter.udpMutex.Unlock()

						redirected = true
					}
				} else {
					redirected = true
					proxyPort = it.ProxyPort
				}

				if redirected {
					// Swap Ethernet addresses
					ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
					// Swap IP addresses
					ip.DstIP, ip.SrcIP = ip.SrcIP, ip.DstIP
					// Change destination port to the transparent proxy
					udp.DstPort = layers.UDPPort(proxyPort)
					// Compute checksums & serialize the packet
					udp.SetNetworkLayerForChecksum(ip)
					serializePacket(b, packet)

					return A.FilterActionRedirect
				} else if socksLocalRouter.IsUDPProxyPort(udp.SrcPort) {
					dstEndpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(udp.DstPort)).String()

					socksLocalRouter.udpMutex.Lock()
					it, exists := socksLocalRouter.udpEndpoints[dstEndpoint]
					if !exists {
						socksLocalRouter.udpMutex.Unlock()
						return A.FilterActionPass
					}
					socksLocalRouter.udpMutex.Unlock()

					// Redirect the packet back to the original destination
					udp.SrcPort = layers.UDPPort(it.DstPort)
					// Swap Ethernet addresses
					ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
					// Swap IP addresses
					ip.DstIP, ip.SrcIP = ip.SrcIP, ip.DstIP
					// Compute checksums & serialize the packet
					udp.SetNetworkLayerForChecksum(ip)
					serializePacket(b, packet)

					return A.FilterActionRedirect
				}
			}
		}

		return A.FilterActionPass
	})

	socksLocalRouter.filter = filter

	// Set up ICMP filter to pass all ICMP traffic
	icmpFilter := D.NewFilter()
	icmpFilter.SetAction(A.FilterActionPass)
	icmpFilter.SetDirection(D.PacketDirectionBoth)
	icmpFilter.SetProtocol(1) // ICMP protocol

	// Get static filter and add ICMP filter
	staticFilter, err := D.GetStaticFilter(api, A.FilterActionRedirect)
	if err != nil {
		return nil, fmt.Errorf("failed to get static filter: %v", err)
	}

	// Add the ICMP filter to the static filters list and apply all filters
	staticFilter.AddFilter(icmpFilter)

	// Apply static filter
	if err := staticFilter.Apply(); err != nil {
		return nil, fmt.Errorf("failed to apply static filter: %v", err)
	}

	socksLocalRouter.staticFilter = staticFilter

	return socksLocalRouter, nil
}

// Close stops the router and resets the static filter.
func (s *SocksLocalRouter) Close() error {
	s.Stop()
	if s.staticFilter != nil {
		s.staticFilter.Reset()
	}
	return nil
}

// Start activates the router and its proxy servers.
func (s *SocksLocalRouter) Start() error {
	s.Lock()
	defer s.Unlock()

	if s.isActive {
		return fmt.Errorf("SocksLocalRouter is already active")
	}

	for _, server := range s.proxyServers {
		s.wg.Add(1)
		go func(server *TransparentProxy) {
			defer s.wg.Done()
			if err := server.Start(s.ctx); err != nil {
				log.Printf("failed to start proxy server: %v", err)
			}
		}(server)
	}

	if s.updateNetworkConfiguration() {
		if err := s.filter.StartFilter(int(s.ifIndex)); err != nil {
			return fmt.Errorf("Failed to start filter: %v", err)
		}
		log.Println("Filter engine has been started using adapter: ", s.defaultAdapter.Name)
	}

	// Register for network interface change notifications
	handle, err := N.NotifyIpInterfaceChange(s.ipInterfaceChangedCallback, 0, true)
	if err != nil {
		log.Println(fmt.Errorf("NotifyIpInterfaceChange failed: %v", err))
	} else {
		s.ifNotifyHandle = handle
	}

	s.isActive = true
	return nil
}

// Stop deactivates the router and its proxy servers.
func (s *SocksLocalRouter) Stop() error {
	s.Lock()
	defer s.Unlock()

	if !s.isActive {
		return fmt.Errorf("SocksLocalRouter is already stopped")
	}

	// Cancel network interface change notifications
	if err := N.CancelMibChangeNotify2(s.ifNotifyHandle); err != nil {
		return fmt.Errorf("CancelMibChangeNotify2 failed: %v", err)
	}
	windows.CloseHandle(s.ifNotifyHandle)

	s.filter.StopFilter()

	for _, server := range s.proxyServers {
		server.Stop()
	}

	s.cancel()
	s.wg.Wait()

	s.isActive = false
	return nil
}

// IsDriverLoaded checks if the NDIS driver is loaded.
func (s *SocksLocalRouter) IsDriverLoaded() bool {
	return s.IsDriverLoaded()
}

// AddSocks5Proxy adds a new SOCKS5 proxy to the router.
func (s *SocksLocalRouter) AddSocks5Proxy(endpoint *string) (int, error) {
	dialer, err := socks5.NewDialer(*endpoint)
	if err != nil {
		return -1, fmt.Errorf("failed to parse endpoint: %v", err)
	}

	endpointIP, endpointPort, err := parseEndpoint(dialer.ProxyAddress)
	if err != nil {
		return -1, fmt.Errorf("failed to parse endpoint: %v", err)
	}

	// Construct filter objects for the TCP and UDP traffic to and from the proxy server
	// These filters are used to decide which packets to pass or drop
	// They are configured to match packets based on their source/destination IP and port numbers
	// and their protocol (TCP or UDP)
	socks5TcpProxyFilterOut := D.NewFilter().
		SetDestAddress(endpointIP.IP).
		SetDestPort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(D.PacketDirectionOut).
		SetProtocol(syscall.IPPROTO_TCP)

	socks5TcpProxyFilterIn := D.NewFilter().
		SetSourceAddress(endpointIP.IP).
		SetSourcePort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(D.PacketDirectionIn).
		SetProtocol(syscall.IPPROTO_TCP)

	socks5UdpProxyFilterOut := D.NewFilter().
		SetDestAddress(endpointIP.IP).
		SetDestPort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(D.PacketDirectionOut).
		SetProtocol(syscall.IPPROTO_UDP)

	socks5UdpProxyFilterIn := D.NewFilter().
		SetSourceAddress(endpointIP.IP).
		SetSourcePort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(D.PacketDirectionIn).
		SetProtocol(syscall.IPPROTO_UDP)

	// Get static filter and add SOCKS5 filters
	staticFilter, err := D.GetStaticFilter(s.NdisApi, A.FilterActionRedirect)
	if err != nil {
		return -1, fmt.Errorf("failed to get static filter: %v", err)
	}

	// Add the filters to a filter list
	// Apply all the filters to the network traffic
	staticFilter.AddFilter(socks5TcpProxyFilterOut)
	staticFilter.AddFilter(socks5TcpProxyFilterIn)
	staticFilter.AddFilter(socks5UdpProxyFilterOut)
	staticFilter.AddFilter(socks5UdpProxyFilterIn)

	// Apply static filter
	if err := staticFilter.Apply(); err != nil {
		return -1, fmt.Errorf("failed to apply static filter: %v", err)
	}

	// Create and add new transparent proxy
	transparentProxy := NewTransparentProxy(0, dialer,
		func(conn net.Conn) (net.IP, layers.TCPPort, error) { // tcp
			s.tcpMutex.RLock()
			value, ok := s.tcpConnections[conn.RemoteAddr().String()]
			s.tcpMutex.RUnlock()

			if !ok {
				return net.IPv4zero, 0, fmt.Errorf("could not find original destination")
			}

			return value.DstIP, value.DstPort, nil
		},
		func(addr net.Addr) (net.IP, layers.UDPPort, error) { // udp
			s.udpMutex.RLock()
			value, ok := s.udpEndpoints[addr.String()]
			s.udpMutex.RUnlock()

			if !ok {
				return net.IPv4zero, 0, fmt.Errorf("could not find original destination")
			}

			return value.DstIP, value.DstPort, nil
		})

	s.proxyServers = append(s.proxyServers, transparentProxy)

	return len(s.proxyServers) - 1, nil
}

// AssociateProcessNameToProxy associates a process name with a proxy ID.
func (s *SocksLocalRouter) AssociateProcessNameToProxy(processName string, proxyID int) error {
	s.Lock()
	defer s.Unlock()

	if proxyID >= len(s.proxyServers) {
		return fmt.Errorf("AssociateProcessNameToProxy: proxy index is out of range")
	}
	s.nameToProxy[processName] = proxyID

	return nil
}

// GetProxyPortTCP retrieves the TCP proxy port for a given process.
func (s *SocksLocalRouter) GetProxyPortTCP(process *N.ProcessInfo) uint16 {
	s.Lock()
	defer s.Unlock()

	for name, proxyID := range s.nameToProxy {
		if strings.Contains(process.PathName, name) {
			if proxyID < len(s.proxyServers) && s.proxyServers[proxyID] != nil {
				return s.proxyServers[proxyID].GetLocalTcpProxyPort()
			}
		}
	}

	return 0
}

// GetProxyPortUDP retrieves the UDP proxy port for a given process.
func (s *SocksLocalRouter) GetProxyPortUDP(process *N.ProcessInfo) uint16 {
	s.Lock()
	defer s.Unlock()

	for name, proxyID := range s.nameToProxy {
		if strings.Contains(process.PathName, name) {
			if proxyID < len(s.proxyServers) && s.proxyServers[proxyID] != nil {
				return s.proxyServers[proxyID].GetLocalUdpProxyPort()
			}
		}
	}

	return 0
}

// IsTCPProxyPort checks if a given port is used by any TCP proxy.
func (s *SocksLocalRouter) IsTCPProxyPort(port layers.TCPPort) bool {
	s.Lock()
	defer s.Unlock()

	for _, server := range s.proxyServers {
		if server.GetLocalTcpProxyPort() == uint16(port) {
			return true
		}
	}
	return false
}

// IsUDPProxyPort checks if a given port is used by any UDP proxy.
func (s *SocksLocalRouter) IsUDPProxyPort(port layers.UDPPort) bool {
	s.Lock()
	defer s.Unlock()

	for _, server := range s.proxyServers {
		if server.GetLocalUdpProxyPort() == uint16(port) {
			return true
		}
	}
	return false
}

// updateNetworkConfiguration updates the network configuration based on the current state of the IP interfaces.
func (s *SocksLocalRouter) updateNetworkConfiguration() bool {
	// Attempts to reconfigure the filter. If it fails, logs an error.
	if err := s.filter.Reconfigure(); err != nil {
		log.Println("Failed to update WinpkFilter network interfaces:", err)
	}

	adapterInfo, adapters, err := N.GetNetworkAdapterInfo(s.NdisApi)
	if err != nil {
		log.Fatalf("Failed to get network adapter info: %v", err)
		return false
	}
	s.adapters = adapters
	selectedAdapter := adapterInfo[0]

	defaultAdapter, err := N.GetBestInterface(adapterInfo, "8.8.8.8")
	if err != nil {
		log.Println(fmt.Printf("Failed to find best network adapter: %v\n Using very first adapter: %s", err, selectedAdapter.Name))
	} else {
		selectedAdapter = defaultAdapter

		log.Println("Detected default interface: ", defaultAdapter.Name)
	}

	s.ifIndex = selectedAdapter.AdapterIndex
	s.defaultAdapter = selectedAdapter

	return true
}

// This is a callback function to handle changes in the IP interface, typically invoked when there are network changes.
func (s *SocksLocalRouter) ipInterfaceChangedCallback(callerContext uintptr, row *windows.MibIpInterfaceRow, notificationType N.MibNotificationType) uintptr {
	adapterInfo, adapters, err := N.GetNetworkAdapterInfo(s.NdisApi)
	if err != nil {
		log.Fatalf("Failed to get network adapter info: %v", err)
	}
	s.adapters = adapters

	defaultAdapter, err := N.GetBestInterface(adapterInfo, "8.8.8.8")
	if err != nil {
		log.Println(fmt.Printf("IP Interface changed: no internet available: %v\n", err))
		return 0
	}

	selectedAdapter := defaultAdapter
	if selectedAdapter.AdapterIndex == s.ifIndex {
		// nothing has changed
		return 0
	}

	s.ifIndex = selectedAdapter.AdapterIndex
	s.defaultAdapter = selectedAdapter

	go func() {
		s.filter.StopFilter()
		if s.updateNetworkConfiguration() {
			s.filter.StartFilter(int(s.ifIndex))
		}
	}()

	return 0
}

func serializePacket(b *A.IntermediateBuffer, packet gopacket.Packet) {
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializePacket(buffer, opts, packet)
	if err != nil {
		fmt.Println(fmt.Errorf("Could not serialize modified packet: %s", err))
		return
	}

	serializedBytes := buffer.Bytes()
	copySize := len(serializedBytes)
	copy(b.Buffer[:copySize], serializedBytes[:copySize])
}

// parseEndpoint parses an endpoint string into an IP address and port.
func parseEndpoint(endpoint string) (*net.IPAddr, uint16, error) {
	pos := strings.LastIndex(endpoint, ":")
	if pos == -1 {
		return nil, 0, fmt.Errorf("invalid endpoint format")
	}

	// Extract and validate the IP address.
	ipStr := endpoint[:pos]
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP address")
	}

	// Extract and validate the port number.
	portStr := endpoint[pos+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("invalid port number")
	}

	return &net.IPAddr{IP: ip}, uint16(port), nil
}
