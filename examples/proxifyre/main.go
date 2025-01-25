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

	router, err = NewSocksLocalRouter(api, true)
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
			log.Printf("Failed to add Socks5 proxy for endpoint %s: %v", appSettings.Endpoint, err)
			return
		}

		for _, appName := range appSettings.AppNames {
			if err := router.AssociateProcessNameToProxy(appName, proxyID); err != nil {
				log.Printf("Failed to associate %s with proxy ID %d: %v", appName, proxyID, err)
				return
			}
		}
	}

	if err := router.Start(); err != nil {
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

	if err := router.Stop(); err != nil {
		log.Println(fmt.Sprintf("Error stopping proxy: %s", err.Error()))
	} else {
		log.Println("Socks5 proxy stopped")
	}

	router.Close()
	api.Close()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
