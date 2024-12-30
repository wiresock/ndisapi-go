package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
)

func main() {
	// Start pprof server
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	_, cancel := context.WithCancel(context.Background())
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

	adapterIndex, filename := getInputs(api, adapters)

	// initialize pcap file storage
	f, err := os.Create(filename)
	if err != nil {
		log.Panic(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(A.MAX_ETHER_FRAME, layers.LinkTypeEthernet) // Adjust link type as needed

	filter, err := D.NewFastIOPacketFilter(
		api,
		adapters,
		func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction {
			data := buffer.Buffer

			packet := gopacket.NewPacket(data[:], layers.LayerTypeEthernet, gopacket.Default)

			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(data),
				Length:        len(data),
			}
			w.WritePacket(ci, packet.Data())

			return A.FilterActionPass
		},
		func(handle A.Handle, buffer *A.IntermediateBuffer) A.FilterAction {
			data := buffer.Buffer

			packet := gopacket.NewPacket(data[:], layers.LayerTypeEthernet, gopacket.Default)

			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(data),
				Length:        len(data),
			}
			w.WritePacket(ci, packet.Data())

			return A.FilterActionPass
		}, true)

	if err != nil {
		log.Println(fmt.Errorf("Failed to create simple_packet_filter: %v", err))
		return
	}

	if err := filter.StartFilter(adapterIndex); err != nil {
		log.Panic(err)
	}
	defer filter.StopFilter()

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}

func getInputs(api *A.NdisApi, adapters *A.TcpAdapterList) (int, string) {
	// list adapters
	for i := range adapters.AdapterCount {
		adapterName := api.ConvertWindows2000AdapterName(string(adapters.AdapterNameList[i][:]))
		fmt.Println(i, "->", adapterName)
	}

	fmt.Print("\nEnter the adapter index: ")
	reader := bufio.NewReader(os.Stdin)
	adapterIndexStr, err := reader.ReadString('\n')
	if err != nil {
		log.Panic(fmt.Errorf("Failed to read adapter index: %v", err))
	}
	adapterIndexStr = strings.TrimSpace(adapterIndexStr)
	adapterIndex, err := strconv.Atoi(adapterIndexStr)
	if err != nil {
		log.Panic(fmt.Errorf("Invalid adapter index: %v", err))
	}

	if adapterIndex < 0 || adapterIndex >= int(adapters.AdapterCount) {
		log.Panic(fmt.Errorf("Invalid adapter index"))
	}

	// Ask for filename
	fmt.Print("Enter the filename to save packets: ")
	var filename string
	fmt.Scanln(&filename)
	if !strings.HasSuffix(filename, ".pcap") {
		filename += ".pcap"
	}

	return adapterIndex, filename
}
