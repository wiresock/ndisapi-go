# Windows Packet Filter Socks5 Simple Example

This example demonstrates how to use the Windows Packet Filter to redirect the selected local process through a specified SOCKS5 proxy. In this case, we will redirect Firefox browser traffic through an SSH tunnel.

## Prerequisites

* Local SOCKS5 proxy (e.g., using an SSH command such as `ssh user@domain.com -D 8080`)

## Usage

Clone the repository:

```sh
git clone https://github.com/wiresock/ndisapi-go.git
```

Start your local SOCKS5 proxy. For example, using an SSH command:

```sh
ssh user@domain.com -D 8080
```

This command will expose a SOCKS5 proxy on localhost 127.0.0.1:8080.

Then run:

```sh
cd .\examples\socksify
go run main.go
```

You will be prompted to enter the adapter index, application name, SOCKS5 endpoint, username, and password. For example:

```out
Enter the adapter index: 0
Enter the application name: firefox.exe
Enter the SOCKS5 endpoint (127.0.0.1:8080): 127.0.0.1:8080
Enter the SOCKS5 username (leave empty if not required): 
Enter the SOCKS5 password (leave empty if not required): 
```

After completing these steps, all traffic from the specified application (in this case, the Firefox browser) will be redirected through the transparent local proxy and then through the SOCKS5 proxy exposed by the SSH command at 127.0.0.1:8080.

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
cd ./examples/socksify
go run main.go
```
