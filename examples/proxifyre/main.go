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
)

var (
	api    *A.NdisApi
	router *SocksLocalRouter
)

func main() {
	api, err := A.NewNdisApi()
	if err != nil {
		log.Println(fmt.Errorf("Failed to create NDIS API instance: %v", err))
		return
	}

	if !api.IsDriverLoaded() {
		log.Fatalln("windows packet filter driver is not installed")
	}

	router, err := setupProxyRouter(api)
	if err != nil {
		log.Fatalf("Failed to setup proxy router: %v", err)
	}

	// wait for interruption
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}

	// close the router
	router.Close()
	api.Close()
}

func setupProxyRouter(api *A.NdisApi) (*SocksLocalRouter, error) {
	router, err := NewSocksLocalRouter(api, true)
	if err != nil {
		return nil, fmt.Errorf("Failed to create SOCKS5 Local Router instance: %v", err)
	}

	// Load configuration from JSON file
	configFilePath := "config.json"
	configFile, err := os.Open(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open config file: %v", err)
	}
	defer configFile.Close()

	var serviceSettings struct {
		Proxies []struct {
			AppNames []string `json:"appNames"`
			Endpoint string   `json:"endpoint"`
		} `json:"proxies"`
	}

	if err := json.NewDecoder(configFile).Decode(&serviceSettings); err != nil {
		log.Fatalf("Failed to decode config file: %v", err)
	}

	// Add SOCKS5 proxies
	for _, appSettings := range serviceSettings.Proxies {
		proxyID, err := router.AddSocks5Proxy(&appSettings.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("Failed to add Socks5 proxy for endpoint %s: %v", appSettings.Endpoint, err)
		}

		for _, appName := range appSettings.AppNames {
			if err := router.AssociateProcessNameToProxy(appName, proxyID); err != nil {
				return nil, fmt.Errorf("Failed to associate %s with proxy ID %d: %v", appName, proxyID, err)
			}
		}
	}

	if err := router.Start(); err != nil {
		return nil, fmt.Errorf("Error starting filter: %s", err.Error())
	}
	log.Println("SOCKS5 local router has been started.")

	return router, nil
}
