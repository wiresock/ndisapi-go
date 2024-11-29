package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	_ "net/http/pprof"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"
	P "github.com/wiresock/ndisapi-go/proxy"
)

var (
	api    *A.NdisApi
	proxy  *P.SocksLocalRouter
	mapper sync.Map
)

var (
	adapterIndex int
	localPort    uint16
	appName      string
	endpoint     string
	username     string
	password     string
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	api, err := A.NewNdisApi()
	if err != nil {
		log.Println(fmt.Errorf("Failed to create NDIS API instance: %v", err))
		return
	}
	defer api.Close()

	// Get adapter information
	adapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		log.Panic(err)
	}

	// list adapters
	for i := range adapters.AdapterCount {
		adapterName := api.ConvertWindows2000AdapterName(string(adapters.AdapterNameList[i][:]))
		fmt.Println(i, "->", adapterName)
	}

	// read proxy data from input
	if err := getUserInput(adapters); err != nil {
		log.Println(err)
		return
	}

	// Initialize process lookup
	processLookup, err := N.NewProcessLookup()
	if err != nil {
		log.Panic("Error creating process lookup:", err)
	}

	tcpRedirect := D.NewTcpLocalRedirector()
	defer tcpRedirect.Stop()

	proxy := P.NewTransparentProxy(0, endpoint, username, password, func(conn net.Conn) (string, error) {
		address := strings.Split(conn.RemoteAddr().String(), ":")

		remoteAddress := net.ParseIP(address[0])
		port, err := strconv.Atoi(address[1])
		if err != nil {
			return "", err
		}

		if value, ok := mapper.Load(int(port)); ok {
			mapper.Delete(int(port))

			return fmt.Sprintf("%s:%d", remoteAddress.String(), value.(uint16)), nil
		}

		return "", fmt.Errorf("could not find original destination")
	})
	defer proxy.Stop()

	filter, err := D.NewSimplePacketFilter(api, adapters, nil, func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction {
		port := proxy.GetLocalProxyPort()

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
					return A.FilterActionPass
				}

				process, err = processLookup.LookupProcessForTcp(ipSession)
				if err != nil {
					return A.FilterActionPass
				}
			}

			if strings.Contains(process.PathName, appName) {
				if (tcpHeader.Flags & (N.TH_SYN | N.TH_ACK)) == N.TH_SYN {
					mapper.Store(
						int(A.Ntohs(tcpHeader.SourcePort)),
						A.Ntohs(tcpHeader.DestPort),
					)
				}

				if tcpRedirect.ProcessClientToServerPacket(buffer, A.Htons(port)) {
					A.RecalculateTCPChecksum(buffer)
					A.RecalculateIPChecksum(buffer)

					buffer.DeviceFlags = A.PACKET_FLAG_ON_RECEIVE
				}
			} else if A.Ntohs(tcpHeader.SourcePort) == port {
				if tcpRedirect.ProcessServerToClientPacket(buffer) {
					A.RecalculateTCPChecksum(buffer)
					A.RecalculateIPChecksum(buffer)
					buffer.DeviceFlags = A.PACKET_FLAG_ON_RECEIVE
				}
			}
		}

		return A.FilterActionPass
	})
	if err != nil {
		log.Println(fmt.Errorf("Failed to create simple_packet_filter: %v", err))
		return
	}

	filter.StartFilter(adapterIndex)
	defer filter.StopFilter()

	proxy.Start(ctx)

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}

func getUserInput(adapters *A.TcpAdapterList) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("\nEnter the adapter index: ")
	adapterIndexStr, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("Failed to read adapter index: %v", err)
	}
	adapterIndexStr = strings.TrimSpace(adapterIndexStr)
	adapterIndex, err = strconv.Atoi(adapterIndexStr)
	if err != nil {
		return fmt.Errorf("Invalid adapter index: %v", err)
	}

	if adapterIndex < 0 || adapterIndex >= int(adapters.AdapterCount) {
		return fmt.Errorf("Invalid adapter index")
	}

	fmt.Print("\nEnter the application name: ")
	appName, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("Failed to read application name: %v", err)
	}
	appName = strings.TrimSpace(appName)

	for {
		fmt.Print("\nEnter the SOCKS5 endpoint: ")
		endpoint, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("Failed to read SOCKS5 endpoint: %v", err)
		}
		endpoint = strings.TrimSpace(endpoint)
		if len(endpoint) > 0 {
			break
		}
		fmt.Println("Endpoint must not be empty.")
	}

	for {
		fmt.Print("\nEnter the SOCKS5 username (leave empty if not required): ")
		username, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("Failed to read SOCKS5 username: %v", err)
		}
		username = strings.TrimSpace(username)
		if len(username) <= 255 {
			break
		}
		fmt.Println("Username must not be greater than 255 characters.")
	}

	for {
		fmt.Print("\nEnter the SOCKS5 password (leave empty if not required): ")
		password, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("Failed to read SOCKS5 password: %v", err)
		}
		password = strings.TrimSpace(password)
		if len(password) <= 255 {
			break
		}
		fmt.Println("Password must not be greater than 255 characters.")
	}

	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
