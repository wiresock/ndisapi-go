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

	A "github.com/amir-devman/ndisapi-go"
	D "github.com/amir-devman/ndisapi-go/driver"
	N "github.com/amir-devman/ndisapi-go/netlib"
)

type SupportedProtocols int

const (
	TCP SupportedProtocols = iota
	UDP
	Both
)

type SocksLocalRouter struct {
	sync.Mutex

	api *A.NdisApi

	tcpMapper sync.Map

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	proxyServers []*TransparentProxy
	nameToProxy  map[string]int
	ifIndex      uint32

	tcpRedirect  *D.TcpLocalRedirector
	process      *N.ProcessLookup
	filter       *D.QueuedPacketFilter
	staticFilter *D.StaticFilter

	isActive bool
}

func NewSocksLocalRouter(api *A.NdisApi) (*SocksLocalRouter, error) {
	tcpRedirect := D.NewTcpLocalRedirector()

	adapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, err
	}

	var selectedAdapter uint32

	interfaces, _ := net.Interfaces()
	firstInterface := interfaces[0]

	for i := range adapters.AdapterCount {
		friendlyName := api.ConvertWindows2000AdapterName(string(adapters.AdapterNameList[i][:]))
		if firstInterface.Name == friendlyName {
			selectedAdapter = i
			log.Println("Selected interface:", friendlyName)
			break
		}
	}

	processLookup, err := N.NewProcessLookup()
	if err != nil {
		fmt.Println("Error creating process lookup:", err)
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	socksLocalRouter := &SocksLocalRouter{
		api: api,

		ctx:    ctx,
		cancel: cancel,

		nameToProxy: make(map[string]int),
		ifIndex:     selectedAdapter,

		tcpRedirect: tcpRedirect,
		process:     processLookup,

		isActive: false,
	}

	filter, err := D.NewQueuedPacketFilter(api, adapters, nil, func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction {
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
					// fmt.Println("Error actualizing process:", err)
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
			} else if socksLocalRouter.IsTcpProxyPort(A.Ntohs(tcpHeader.SourcePort)) {
				if socksLocalRouter.tcpRedirect.ProcessServerToClientPacket(buffer) {
					return A.FilterActionRedirect
				}
			}
		}

		return A.FilterActionPass
	})

	socksLocalRouter.filter = filter

	// Set up ICMP filter to pass all ICMP traffic
	icmpFilter := N.NewFilter()
	icmpFilter.SetAction(A.FilterActionPass)
	icmpFilter.SetDirection(A.PacketDirectionBoth)
	icmpFilter.SetProtocol(A.IPPROTO_ICMP)

	staticFilter, err := D.GetStaticFilter(api, A.FilterActionRedirect)
	if err != nil {
		return nil, fmt.Errorf("failed to get static filter: %v", err)
	}

	// Add the ICMP filter to the static filters list and apply all filters
	staticFilter.AddFilter(icmpFilter)

	if err := staticFilter.Apply(); err != nil {
		return nil, fmt.Errorf("failed to apply static filter: %v", err)
	}

	socksLocalRouter.staticFilter = staticFilter

	return socksLocalRouter, nil
}

func (S *SocksLocalRouter) Close() error {
	S.Stop()
	S.staticFilter.Reset()
	return nil
}

func (S *SocksLocalRouter) Start() error {
	S.Lock()
	defer S.Unlock()

	if S.isActive {
		return fmt.Errorf("SocksLocalRouter is already active")
	}

	for _, server := range S.proxyServers {
		S.wg.Add(1)
		go func(server *TransparentProxy) {
			defer S.wg.Done()
			if err := server.Start(S.ctx); err != nil {
				log.Printf("failed to start proxy server: %v", err)
			}
		}(server)
	}

	if err := S.filter.StartFilter(int(S.ifIndex)); err != nil {
		return fmt.Errorf("Failed to start filter: %v", err)
	}

	S.isActive = true
	return nil
}

func (S *SocksLocalRouter) Stop() error {
	S.Lock()
	defer S.Unlock()

	if !S.isActive {
		return fmt.Errorf("SocksLocalRouter is already stopped")
	}

	S.filter.StopFilter()

	for _, server := range S.proxyServers {
		server.Stop()
	}

	S.cancel()
	S.wg.Wait()

	S.isActive = false
	return nil
}

func (S *SocksLocalRouter) IsDriverLoaded() bool {
	return S.api.IsDriverLoaded()
}

func (S *SocksLocalRouter) AddSocks5Proxy(endpoint *string, protocol SupportedProtocols, start bool, login *string, password *string) (int, error) {
	endpointIP, endpointPort, err := parseEndpoint(*endpoint)
	if err != nil {
		return -1, fmt.Errorf("failed to parse endpoint: %v", err)
	}

	socks5TcpProxyFilterOut := N.NewFilter().
		SetDestAddress(endpointIP.IP).
		SetDestPort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(A.PacketDirectionOut).
		SetProtocol(A.IPPROTO_TCP)

	socks5TcpProxyFilterIn := N.NewFilter().
		SetSourceAddress(endpointIP.IP).
		SetSourcePort([2]uint16{uint16(endpointPort), uint16(endpointPort)}).
		SetAction(A.FilterActionPass).
		SetDirection(A.PacketDirectionIn).
		SetProtocol(A.IPPROTO_TCP)

	staticFilter, err := D.GetStaticFilter(S.api, A.FilterActionRedirect)
	if err != nil {
		return -1, fmt.Errorf("failed to get static filter: %v", err)
	}

	staticFilter.AddFilter(socks5TcpProxyFilterOut)
	staticFilter.AddFilter(socks5TcpProxyFilterIn)

	if err := staticFilter.Apply(); err != nil {
		return -1, fmt.Errorf("failed to apply static filter: %v", err)
	}

	transparentProxy := NewTransparentProxy("0.0.0.0:0", *endpoint, *login, *password, func(conn net.Conn) (string, error) {
		var remoteAddress net.IP

		address := strings.Split(conn.RemoteAddr().String(), ":")

		remoteAddress = net.ParseIP(address[0])
		port, err := strconv.Atoi(address[1])
		if err != nil {
			return "", err
		}

		if value, ok := S.tcpMapper.Load(int(port)); ok {
			S.tcpMapper.Delete(int(port))

			return fmt.Sprintf("%s:%d", remoteAddress.String(), value.(uint16)), nil
		}

		return "", fmt.Errorf("could not find original destination")
	})

	S.proxyServers = append(S.proxyServers, transparentProxy)

	return len(S.proxyServers) - 1, nil
}

func (S *SocksLocalRouter) AssociateProcessNameToProxy(processName string, proxyID int) error {
	S.Lock()
	defer S.Unlock()

	if proxyID >= len(S.proxyServers) {
		return fmt.Errorf("AssociateProcessNameToProxy: proxy index is out of range")
	}
	S.nameToProxy[processName] = proxyID

	return nil
}

func (S *SocksLocalRouter) GetProxyPortTCP(process *N.NetworkProcess) uint16 {
	S.Lock()
	defer S.Unlock()

	for name, proxyID := range S.nameToProxy {
		if strings.Contains(process.PathName, name) {
			if proxyID < len(S.proxyServers) && S.proxyServers[proxyID] != nil {
				return S.proxyServers[proxyID].GetLocalProxyPort()
			}
		}
	}

	return 0
}

func (S *SocksLocalRouter) IsTcpProxyPort(port uint16) bool {
	S.Lock()
	defer S.Unlock()

	for _, server := range S.proxyServers {
		if server.GetLocalProxyPort() == port {
			return true
		}
	}
	return false
}

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
