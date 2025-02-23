package main

import (
	"dnsbox/dnsbox/dns"
	"fmt"
)

func main() {
	client := dns.NewClient("8.8.8.8")
	packet, err := client.Query("google.com")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("recvPacket: %+v", packet)
}
