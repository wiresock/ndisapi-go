//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	A "github.com/wiresock/ndisapi-go"
	P "github.com/wiresock/ndisapi-go/proxy"
)

var (
	api   *A.NdisApi
	proxy *P.SocksLocalRouter
)

func main() {

	api, err := A.NewNdisApi()
	if err != nil {
		log.Println(fmt.Errorf("Failed to create NDIS API instance: %v", err))
		return
	}

	proxy, err = P.NewSocksLocalRouter(api)
	if err != nil {
		log.Println(fmt.Errorf("Failed to create SOCKS5 Local Router instance: %v", err))
		return
	}

	// Load configuration from JSON file
	configFilePath := "config.json"
	configFile, err := os.Open(configFilePath)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()

	var serviceSettings struct {
		Proxies  []struct {
			AppNames            []string `json:"appNames"`
			Socks5ProxyEndpoint string   `json:"socks5ProxyEndpoint"`
			Username            *string  `json:"username"`
			Password            *string  `json:"password"`
			SupportedProtocols  []string `json:"supportedProtocols"`
		} `json:"proxies"`
	}

	if err := json.NewDecoder(configFile).Decode(&serviceSettings); err != nil {
		log.Fatalf("Failed to decode config file: %v", err)
	}

	// Add SOCKS5 proxies
	for _, appSettings := range serviceSettings.Proxies {
		var protocol P.SupportedProtocols
		if len(appSettings.SupportedProtocols) == 0 || (contains(appSettings.SupportedProtocols, "TCP") && contains(appSettings.SupportedProtocols, "UDP")) {
			protocol = P.Both
		} else if contains(appSettings.SupportedProtocols, "TCP") {
			protocol = P.TCP
		} else if contains(appSettings.SupportedProtocols, "UDP") {
			protocol = P.UDP
		}

		proxyID, err := proxy.AddSocks5Proxy(&appSettings.Socks5ProxyEndpoint, protocol, true, appSettings.Username, appSettings.Password)
		if err != nil {
			log.Printf("Failed to add Socks5 proxy for endpoint %s: %v", appSettings.Socks5ProxyEndpoint, err)
			return
		}

		for _, appName := range appSettings.AppNames {
			if err := proxy.AssociateProcessNameToProxy(appName, proxyID); err != nil {
				log.Printf("Failed to associate %s with proxy ID %d: %v", appName, proxyID, err)
				return
			}
		}
	}

	if err := proxy.Start(); err != nil {
		log.Println(fmt.Sprintf("Error starting filter: %s", err.Error()))
		return
	}
	log.Println("SOCKS5 local router has been started.")

	// wait for interruption
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}

	if err := proxy.Stop(); err != nil {
		log.Println(fmt.Sprintf("Error stopping proxy: %s", err.Error()))
	} else {
		log.Println("Socks5 proxy stopped")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
