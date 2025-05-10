package main

import (
	"github.com/niioka/dnsbox/dns/server"
)

func main() {
	server := server.NewServer(server.ServerConfig{})
	server.Start()
}
