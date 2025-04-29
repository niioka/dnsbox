package main

import "github.com/niioka/dnsbox/dns"

func main() {
	server := dns.NewServer(dns.ServerConfig{})
	server.Start()
}
