//go:build windows

package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"

	"golang.org/x/sys/windows"
)

// SupportedProtocols defines the supported protocols for the proxy.
type SupportedProtocols int

const (
	TCP SupportedProtocols = iota
	UDP
	Both
)

// SocksLocalRouter handles the routing of SOCKS traffic locally.
type SocksLocalRouter struct {
	sync.Mutex // Mutex to synchronize access to shared resources.
	*A.NdisApi // API instance for interacting with the NDIS API.

	wg sync.WaitGroup // WaitGroup to manage goroutines.

	tcpMapper sync.Map // Map to store TCP port mappings.

	ctx          context.Context // Context and cancel function for managing the router's lifecycle.
	cancel       context.CancelFunc
	proxyServers []*TransparentProxy // List of proxy servers managed by this router.
	nameToProxy  map[string]int      // Map to associate process names with proxy indices.

	ifNotifyHandle windows.Handle
	ifIndex        uint32 // Index of the network interface used.
	adapters       *A.TcpAdapterList
	defaultAdapter *A.NetworkAdapterInfo

	process *N.ProcessLookup // Process lookup instance.

	tcpRedirect  *D.TcpLocalRedirector // TCP redirector instance.
	filter       *D.QueuedPacketFilter // Packet filter instance.
	staticFilter *D.StaticFilter       // Static filter instance.

	isActive bool // Boolean to track the active status of the router.
}

// NewSocksLocalRouter creates a new instance of SocksLocalRouter.
func NewSocksLocalRouter(api *A.NdisApi) (*SocksLocalRouter, error) {
	// Initialize TCP redirector
	tcpRedirect := D.NewTcpLocalRedirector()

	// Get adapter information
	adapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, err
	}

	// Initialize process lookup
	processLookup, err := N.NewProcessLookup()
	if err != nil {
		log.Println("Error creating process lookup:", err)
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

		tcpRedirect: tcpRedirect,
		process:     processLookup,

		adapters: adapters,

		isActive: false,
	}

	// Create packet filter
	filter, err := D.NewQueuedPacketFilter(api, socksLocalRouter.adapters, nil, func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction {
		etherHeaderSize := int(unsafe.Sizeof(A.EtherHeader{}))
		if len(buffer.Buffer) < etherHeaderSize {
			return A.FilterActionPass
		}

		ethernetHeader := (*A.EtherHeader)(unsafe.Pointer(&buffer.Buffer[0]))

		if A.Ntohs(ethernetHeader.Proto) != A.ETH_P_IP {
			return A.FilterActionPass
		}

		ipHeader := (*A.IPHeader)(unsafe.Pointer(&buffer.Buffer[etherHeaderSize]))

		if ipHeader.Protocol == A.IPPROTO_TCP {
			tcpHeader := (*A.TCPHeader)(unsafe.Pointer(&buffer.Buffer[etherHeaderSize+int(ipHeader.HeaderLength())*4]))

			ipSession := N.NewIPSession(net.IP(ipHeader.SourceAddr[:]), net.IP(ipHeader.DestinationAddr[:]), A.Ntohs(tcpHeader.SourcePort), A.Ntohs(tcpHeader.DestPort))
			process, err := processLookup.LookupProcessForTcp(ipSession)
			if process.ID == 0 {
				if err := processLookup.Actualize(true, false); err != nil {
					// log.Println("Error actualizing process:", err)
					return A.FilterActionPass
				}

				process, err = processLookup.LookupProcessForTcp(ipSession)
				if err != nil {
					return A.FilterActionPass
				}
			}

			if port := socksLocalRouter.GetProxyPortTCP(process); port != 0 {
				if (tcpHeader.Flags & (N.TH_SYN | N.TH_ACK)) == N.TH_SYN {
					socksLocalRouter.tcpMapper.Store(
						int(A.Ntohs(tcpHeader.SourcePort)),
						A.Ntohs(tcpHeader.DestPort),
					)
				}

				if socksLocalRouter.tcpRedirect.ProcessClientToServerPacket(buffer, A.Htons(port)) {
					return A.FilterActionRedirect
				}
			} else if socksLocalRouter.IsTCPProxyPort(A.Ntohs(tcpHeader.SourcePort)) {
				if socksLocalRouter.tcpRedirect.ProcessServerToClientPacket(buffer) {
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
	icmpFilter.SetDirection(A.PacketDirectionBoth)
	icmpFilter.SetProtocol(A.IPPROTO_ICMP)

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
	s.tcpRedirect.Stop()
	s.staticFilter.Reset()
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
func (s *SocksLocalRouter) AddSocks5Proxy(endpoint *string, protocol SupportedProtocols, start bool, login *string, password *string) (int, error) {
	endpointIP, endpointPort, err := parseEndpoint(*endpoint)
	if err != nil {
		return -1, fmt.Errorf("failed to parse endpoint: %v", err)
	}

	// Create filters for the SOCKS5 proxy
	socks5TcpProxyFilterOut := D.NewFilter().
		SetDestAddress(endpointIP.IP).
		SetDestPort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(A.PacketDirectionOut).
		SetProtocol(A.IPPROTO_TCP)

	socks5TcpProxyFilterIn := D.NewFilter().
		SetSourceAddress(endpointIP.IP).
		SetSourcePort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(A.PacketDirectionIn).
		SetProtocol(A.IPPROTO_TCP)

	// Get static filter and add SOCKS5 filters
	staticFilter, err := D.GetStaticFilter(s.NdisApi, A.FilterActionRedirect)
	if err != nil {
		return -1, fmt.Errorf("failed to get static filter: %v", err)
	}

	staticFilter.AddFilter(socks5TcpProxyFilterOut)
	staticFilter.AddFilter(socks5TcpProxyFilterIn)

	// Apply static filter
	if err := staticFilter.Apply(); err != nil {
		return -1, fmt.Errorf("failed to apply static filter: %v", err)
	}

	// Create and add new transparent proxy
	transparentProxy := NewTransparentProxy(0, *endpoint, *login, *password, func(conn net.Conn) (string, error) {
		address := strings.Split(conn.RemoteAddr().String(), ":")

		remoteAddress := net.ParseIP(address[0])
		port, err := strconv.Atoi(address[1])
		if err != nil {
			return "", err
		}

		if value, ok := s.tcpMapper.Load(int(port)); ok {
			s.tcpMapper.Delete(int(port))

			return fmt.Sprintf("%s:%d", remoteAddress.String(), value.(uint16)), nil
		}

		return "", fmt.Errorf("could not find original destination")
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
func (s *SocksLocalRouter) GetProxyPortTCP(process *N.NetworkProcess) uint16 {
	s.Lock()
	defer s.Unlock()

	for name, proxyID := range s.nameToProxy {
		if strings.Contains(process.PathName, name) {
			if proxyID < len(s.proxyServers) && s.proxyServers[proxyID] != nil {
				return s.proxyServers[proxyID].GetLocalProxyPort()
			}
		}
	}

	return 0
}

// IsTCPProxyPort checks if a given port is used by any TCP proxy.
func (s *SocksLocalRouter) IsTCPProxyPort(port uint16) bool {
	s.Lock()
	defer s.Unlock()

	for _, server := range s.proxyServers {
		if server.GetLocalProxyPort() == port {
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

	adapterInfo, adapters, err := A.GetNetworkAdapterInfo(s.NdisApi)
	if err != nil {
		log.Fatalf("Failed to get network adapter info: %v", err)
	}
	s.adapters = adapters
	selectedAdapter := adapterInfo[0]

	s.ifIndex = selectedAdapter.AdapterIndex
	s.defaultAdapter = selectedAdapter

	return true
}

// This is a callback function to handle changes in the IP interface, typically invoked when there are network changes.
func (s *SocksLocalRouter) ipInterfaceChangedCallback(callerContext uintptr, row *windows.MibIpInterfaceRow, notificationType N.MibNotificationType) uintptr {
	adapterInfo, adapters, err := A.GetNetworkAdapterInfo(s.NdisApi)
	if err != nil {
		log.Fatalf("Failed to get network adapter info: %v", err)
	}
	s.adapters = adapters

	selectedAdapter := adapterInfo[0]

	if int(selectedAdapter.AdapterIndex) == int(s.ifIndex) {
		// nothing has changed
		return 0
	}

	log.Println("default network adapter has changed. Restart the filter engine.")

	s.ifIndex = uint32(selectedAdapter.AdapterIndex)
	s.defaultAdapter = selectedAdapter

	go func() {
		s.filter.StopFilter()
		if s.updateNetworkConfiguration() {
			s.filter.StartFilter(int(s.ifIndex))
		}
	}()

	return 0
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
