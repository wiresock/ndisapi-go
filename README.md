# NDISAPI-Go

A Go library providing a comprehensive user-mode interface to the Windows Packet Filter driver for high-performance network packet interception and manipulation at the NDIS level.

## Overview

**NDISAPI-Go** is a Go implementation of the NDISAPI library, designed to interact seamlessly with the Windows Packet Filter driver. It offers Go developers a straightforward, safe, and efficient interface for filtering (inspecting and modifying) raw network packets at the NDIS (Network Driver Interface Specification) level of the Windows network stack. This library ensures minimal impact on network performance while providing powerful capabilities for building network applications such as firewalls, packet analyzers, VPNs, and more.

## Features

- **Seamless Integration**: Direct interaction with the Windows Packet Filter driver through a user-mode interface.
- **Packet Interception**: Capture inbound and outbound network packets at the data-link layer.
- **Packet Modification**: Inspect and modify network packets on the fly.
- **Packet Injection**: Inject custom packets into the network stack.
- **Multi-Adapter Support**: Interact with multiple network interfaces simultaneously.
- **High Performance**: Designed for minimal overhead, ensuring efficient network processing.
- **Thread Safety**: Safe for use in concurrent applications.

## Requirements

- **Operating System**: Windows 7 or later (32-bit or 64-bit)
- **Go Version**: Go 1.18 or later
- **Windows Packet Filter Driver**: The driver must be installed on the system.
- **Permissions**: Administrator privileges are required to interact with network drivers and interfaces.

## Installation

1. **Install the Windows Packet Filter Driver**

   Download and install the Windows Packet Filter driver from the official website:

   - [Windows Packet Filter Driver](https://www.ntkernel.com/windows-packet-filter/)

2. **Install the NDISAPI-Go Package**

   Use `go get` to install the package:

   ```sh
   go get github.com/wiresock/ndisapi-go
   ```

## Usage
```go
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
	"syscall"

	"github.com/wiresock/ndisapi-go"
	"github.com/wiresock/ndisapi-go/driver"
)

func main() {
	api, err := ndisapi.NewNdisApi()
	if err != nil {
		log.Panic(fmt.Errorf("failed to create NDIS API instance: %v", err))
	}
	defer api.Close()
	if !api.IsDriverLoaded() {
		log.Fatalf("windows packet filter driver is not installed")
	}
	adapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		log.Panic(err)
	}

	// Get static filter and add ICMP filter
	staticFilter, err := driver.NewStaticFilters(api, true, true)
	if err != nil {
		log.Panic(fmt.Errorf("failed to get static filter: %v", err))
	}

	adapterIndex := getInputs(api, adapters)

	ctx := context.Background()
	filter, err := driver.NewQueuedPacketFilter(
		ctx,
		api,
		adapters,
		func(handle ndisapi.Handle, buffer *ndisapi.IntermediateBuffer) ndisapi.FilterAction {
			// Modify incoming packets here

			return ndisapi.FilterActionPass
		},
		func(handle ndisapi.Handle, buffer *ndisapi.IntermediateBuffer) ndisapi.FilterAction {
			// Modify outgoing packets here

			return ndisapi.FilterActionPass
		})
	if err != nil {
		log.Panic(fmt.Errorf("failed to create queued_packet_filter: %v", err))
	}

	// Allocate a packet filter
	staticFilter.AddFilterBack(&driver.Filter{
		AdapterHandle:      adapters.AdapterHandle[adapterIndex],
		Action:             ndisapi.FilterActionPass,
		SourceAddress:      net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(0, 32)},
	})

	fmt.Printf("\n\nPacket filtering is started...\nPress Ctrl+C to stop.\n\n")
	if err := filter.StartFilter(adapterIndex); err != nil {
		log.Panic(err)
	}
	defer filter.Close()
	defer staticFilter.Close()
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}

func getInputs(api *ndisapi.NdisApi, adapters *ndisapi.TcpAdapterList) int {
	for i := 0; i < int(adapters.AdapterCount); i++ {
		adapterName := api.ConvertWindows2000AdapterName(string(adapters.AdapterNameList[i][:]))
		fmt.Println(i, "->", adapterName)
	}

	fmt.Print("\nEnter the adapter index: ")
	reader := bufio.NewReader(os.Stdin)
	adapterIndexStr, err := reader.ReadString('\n')
	if err != nil {
		log.Panic(fmt.Errorf("failed to read adapter index: %v", err))
	}
	adapterIndexStr = strings.TrimSpace(adapterIndexStr)
	adapterIndex, err := strconv.Atoi(adapterIndexStr)
	if err != nil {
		log.Panic(fmt.Errorf("invalid adapter index: %v", err))
	}

	if adapterIndex < 0 || adapterIndex >= int(adapters.AdapterCount) {
		log.Panic(fmt.Errorf("invalid adapter index"))
	}

	return adapterIndex
}
```

## Documentation

Detailed documentation is available at [pkg.go.dev/github.com/wiresock/ndisapi-go](https://pkg.go.dev/github.com/wiresock/ndisapi-go).

## Examples

Additional examples are available in the `examples` directory:

- **Packet Sniffer**: Capture and display network packets in real-time.
- **Firewall**: Implement packet filtering based on custom rules.
- **Packet Modifier**: Intercept and modify packets before forwarding.
- **Packet Generator**: Create and inject custom packets into the network.

You can find these examples in the [examples](https://github.com/wiresock/ndisapi-go/tree/main/examples) directory of the repository.

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**: Click on the 'Fork' button on the repository page.
2. **Create a Branch**: Create a new branch for your feature or bugfix.
3. **Commit Changes**: Make your changes and commit them with descriptive messages.
4. **Push to Branch**: Push your changes to your forked repository.
5. **Create Pull Request**: Open a pull request to the main repository.

Please ensure that your code adheres to the project's coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Main Contributor and Maintainer**: [amir.devman@gmail.com](mailto:amir.devman@gmail.com). Thank you for your significant contributions to this project. Contact details will be updated later.
- **Windows Packet Filter Driver**: This project relies on the Windows Packet Filter driver developed by [NT Kernel Resources](https://www.ntkernel.com/). Special thanks for providing a powerful tool for network packet filtering.

## Support

If you encounter any issues or have questions, please open an issue on GitHub.

## Disclaimer

Use this library responsibly and ensure compliance with all applicable laws and regulations regarding network traffic interception and modification.
