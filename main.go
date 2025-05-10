package main

import (
	"github.com/niioka/dnsbox/api"
	"github.com/niioka/dnsbox/dns/server"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	var wg sync.WaitGroup

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	apiServer := api.New()
	dnsServer := server.NewServer(server.ServerConfig{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Start DNS Server
		if err := dnsServer.Start(); err != nil {
			log.Errorf("failed to start DNS server: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		// Start API Server
		err := apiServer.Start()
		if err != nil {
			log.Errorf("failed to start API server: %v", err)
		}
	}()
	// 終了を待機する
	<-ch
	log.Info("Shutting down...")
	if err := apiServer.Stop(); err != nil {
		log.Errorf("failed to stop API server: %v", err)
	}

	if err := dnsServer.Stop(); err != nil {
		log.Errorf("failed to stop DNS Server: %v", err)
	}
}
