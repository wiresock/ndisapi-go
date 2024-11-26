# Windows Packet Filter Socks5 Example

This example demonstrates how to use the Windows Packet Filter to redirect the selected local process through a specified SOCKS5 proxy. In this case, we will redirect Firefox browser traffic through an SSH tunnel.

## Prerequisites

* Local SOCKS5 proxy (e.g., using an SSH command such as `ssh user@domain.com -D 8080`)

## Usage

1. Start your local SOCKS5 proxy. For example, using an SSH command:

```bash
ssh user@domain.com -D 8080
```

This command will expose a SOCKS5 proxy on localhost 127.0.0.1:8080.

*Note: run all the commands from the repo root directory*

2. Create `./examples/socks5/config.json`:
```json
{
  "proxies": [
    {
      "appNames": [
        "firefox"
      ],
      "socks5ProxyEndpoint": "127.0.0.1:8080",
      "username": "",
      "password": "",
      "supportedProtocols": [
        "TCP"
      ]
    }
  ]
}
```

```
go run ./examples/socks5/main.go
```

After completing these steps, all traffic from the specified application (in this case, the Firefox browser) will be redirected through the transparent local proxy and then through the SOCKS5 proxy exposed by the SSH command at 127.0.0.1:8080.
