//go:build windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	_ "net/http/pprof"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"
)

var (
	api        *A.NdisApi
	localProxy *TransparentProxy

	processLookup = N.ProcessLookup{}

	mu          sync.RWMutex
	connections map[string]layers.TCPPort = make(map[string]layers.TCPPort)
)

var (
	adapterIndex int    = 0
	localPort    uint16 = 9000
	appName      string = "firefox"
	endpoint     string = "127.0.0.1:8080"
	username     string = ""
	password     string = ""
)

func main() {
	// Start pprof server
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

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

	localProxy := NewTransparentProxy(localPort, endpoint, username, password, func(conn net.Conn) (string, error) {
		mu.Lock()
		value, ok := connections[conn.RemoteAddr().String()]
		mu.Unlock()

		if ok {
			// Get destination port from the connections map
			result := fmt.Sprintf("%s:%d", strings.Split(conn.RemoteAddr().String(), ":")[0], value)
			return result, nil
		}

		return "", fmt.Errorf("could not find original destination")
	})
	defer localProxy.Stop()

	filter, err := D.NewSimplePacketFilter(ctx, api, adapters, nil, func(handle A.Handle, b *A.IntermediateBuffer) A.FilterAction {
		port := localProxy.GetLocalProxyPort()
		packet := gopacket.NewPacket(b.Buffer[:], layers.LayerTypeEthernet, gopacket.Default)

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			return A.FilterActionPass
		}
		ethernet := ethernetLayer.(*layers.Ethernet)
		if ethernet.EthernetType != layers.EthernetTypeIPv4 {
			return A.FilterActionPass
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return A.FilterActionPass
		}

		ip, _ := ipLayer.(*layers.IPv4)
		if ip.Protocol != layers.IPProtocolTCP {
			return A.FilterActionPass
		}
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.SrcIP)), uint16(tcp.SrcPort))
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.DstPort))

		redirected := false
		if tcp.SYN && !tcp.ACK {
			processInfo, err := processLookup.FindProcessInfo(ctx, false, src, dst, false)
			if err == nil && strings.Contains(processInfo.PathName, appName) {
				log.Printf("[TCP] %s - %s -> %s (Redirected)", filepath.Base(processInfo.PathName), src.String(), dst.String())

				connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.SrcPort)).String()

				mu.Lock()
				if _, loaded := connections[connName]; loaded {
				} else {
					connections[connName] = tcp.DstPort
				}
				mu.Unlock()
				redirected = true
			}
		} else {
			connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.SrcPort)).String()

			mu.RLock()
			_, exists := connections[connName]
			mu.RUnlock()
			if exists {
				if tcp.RST || tcp.FIN {
					mu.Lock()
					delete(connections, connName)
					mu.Unlock()

					log.Printf("[TCP] %s - %s (Closed)", src.String(), dst.String())
				} else {
					log.Printf("[TCP] %s - %s", src.String(), dst.String())
				}

				redirected = true
			}
		}

		if redirected {
			// Swap Ethernet addresses
			ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
			// Swap IP addresses
			ip.DstIP, ip.SrcIP = ip.SrcIP, ip.DstIP
			// Change destination port to the transparent proxy
			tcp.DstPort = layers.TCPPort(port)
			// Compute checksums & serialize the packet
			serializePacket(b, packet, ip, tcp)

			log.Printf("[CMS] %s - %s", src.String(), dst.String())

			return A.FilterActionRedirect
		} else if uint16(tcp.SrcPort) == port {
			connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), uint16(tcp.DstPort)).String()

			mu.Lock()
			it, exists := connections[connName]
			if !exists {
				mu.Unlock()
				return A.FilterActionPass
			}

			if tcp.RST || tcp.FIN {
				delete(connections, connName)
				log.Printf("[TCP] %s - %s (Closed)", src.String(), dst.String())
			}
			mu.Unlock()

			// Redirect the packet back to the original destination
			tcp.SrcPort = it
			// Swap Ethernet addresses
			ethernet.SrcMAC, ethernet.DstMAC = ethernet.DstMAC, ethernet.SrcMAC
			// Swap IP addresses
			ip.DstIP, ip.SrcIP = ip.SrcIP, ip.DstIP
			// Compute checksums & serialize the packet
			serializePacket(b, packet, ip, tcp)

			log.Printf("[SMC] %s - %s", src.String(), dst.String())

			return A.FilterActionRedirect
		}

		return A.FilterActionPass
	})
	if err != nil {
		log.Println(fmt.Errorf("Failed to create simple_packet_filter: %v", err))
		return
	}

	filter.StartFilter(adapterIndex)
	defer filter.Close()

	localProxy.Start(ctx)
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}

func serializePacket(b *A.IntermediateBuffer, packet gopacket.Packet, ip *layers.IPv4, tcp *layers.TCP) {
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}
	tcp.SetNetworkLayerForChecksum(ip)
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

	for {
		fmt.Print("\nEnter the application name: ")
		appName, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("Failed to read application name: %v", err)
		}
		appName = strings.TrimSpace(appName)
		if len(appName) > 0 {
			break
		}
		fmt.Println("Application name must not be empty.")
	}

	for {
		fmt.Print("\nEnter the SOCKS5 endpoint (127.0.0.1:8080): ")
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
