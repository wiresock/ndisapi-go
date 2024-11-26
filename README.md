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
- **Go Version**: Go 1.15 or later
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

Here's a simple example demonstrating how to capture and modify network packets:

```go
package main

import (
    "fmt"
    "log"

    "github.com/wiresock/ndisapi-go"
)

func main() {
    // Initialize the NDISAPI driver interface
    api, err := ndisapi.NewNDISAPI()
    if err != nil {
        log.Fatal("Failed to initialize NDISAPI:", err)
    }
    defer api.Close()

    // Retrieve the list of network adapters
    adapters, err := api.GetAdapterList()
    if err != nil {
        log.Fatal("Failed to get adapter list:", err)
    }

    for idx, adapter := range adapters {
        fmt.Printf("Adapter %d: %s\n", idx, adapter.FriendlyName)
    }

    // Select the first adapter for packet interception
    adapter := adapters[0]

    // Set adapter mode to capture and modify packets
    err = api.SetAdapterMode(adapter.Handle, ndisapi.MSTCP_FLAG_TUNNEL|ndisapi.MSTCP_FLAG_LOOPBACK_BLOCK)
    if err != nil {
        log.Fatal("Failed to set adapter mode:", err)
    }

    // Allocate a packet filter
    filter := ndisapi.NewStaticFilter()
    filter.AdapterHandle = adapter.Handle
    filter.ValidFields = ndisapi.NETWORK_LAYER_VALID
    filter.SourceIP = ndisapi.IPAddressFromString("192.168.1.100")
    filter.SourceIPMask = ndisapi.IPAddressFromString("255.255.255.255")
    filter.FilterAction = ndisapi.FILTER_PACKET_PASS

    // Set the packet filter
    err = api.SetPacketFilterTable([]ndisapi.StaticFilter{filter})
    if err != nil {
        log.Fatal("Failed to set packet filter table:", err)
    }

    // Start capturing packets
    packetChan := make(chan ndisapi.Packet)
    go func() {
        err := api.ReadPackets(adapter.Handle, packetChan)
        if err != nil {
            log.Fatal("Error reading packets:", err)
        }
    }()

    // Process packets
    for packet := range packetChan {
        // Inspect or modify the packet as needed
        fmt.Printf("Captured packet of size %d bytes\n", len(packet.Data))

        // For example, modify packet data here

        // Forward the packet
        err = api.SendPacketToAdapter(adapter.Handle, packet)
        if err != nil {
            fmt.Println("Error sending packet to adapter:", err)
        }
    }
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

## Building from Source

Clone the repository:

```sh
git clone https://github.com/wiresock/ndisapi-go.git
```

Navigate to the project directory:

```sh
cd ndisapi-go
```

Build your application:

```sh
go build
```

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

- **Main Contributor and Maintainer**: [amir.devman@*****.com](mailto:amir.devman@*****.com). Thank you for your significant contributions to this project. Contact details will be updated later.
- **Windows Packet Filter Driver**: This project relies on the Windows Packet Filter driver developed by [NT Kernel Resources](https://www.ntkernel.com/). Special thanks for providing a powerful tool for network packet filtering.

## Support

If you encounter any issues or have questions, please open an issue on GitHub.

## Disclaimer

Use this library responsibly and ensure compliance with all applicable laws and regulations regarding network traffic interception and modification.