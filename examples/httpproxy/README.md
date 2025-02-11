# Windows Packet Filter HTTP Proxy Example

This example demonstrates how to use the Windows Packet Filter to redirect the selected local process through a specified HTTP proxy. In this case, we will redirect Firefox browser traffic through an HTTP proxy.

## Prerequisites

* HTTP proxy server

## Usage

### Clone the Repository

First, clone the repository:

```sh
git clone https://github.com/wiresock/ndisapi-go.git
```

Then run:
```sh
go run .\examples\httpproxy\main.go
```

You will be prompted to enter the adapter index, application name, HTTP-Proxy endpoint, username, and password. For example:

```out
Enter the adapter index: 0
Enter the application name: chrome.exe
Enter the HTTP-Proxy endpoint (127.0.0.1:8080): 127.0.0.1:8080
Enter the HTTP-Proxy username (leave empty if not required): 
Enter the HTTP-Proxy password (leave empty if not required): 
```

After completing these steps, all traffic from port 80 and 443 of the specified application (in this case, the Chrome browser) will be redirected through the transparent local proxy and then through the HTTP Proxy.

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
go build ./examples/httpproxy
```
