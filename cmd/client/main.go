package main

import (
	"fmt"
	"github.com/niioka/dnsbox/dns"
)

func main() {
	// client := dns.NewClient("8.8.8.8")
	client := dns.NewClient("127.0.0.1")
	answers, err := client.ResolveTXT("_dmarc.google.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(";; ANSWER SECTION:")
	for _, answer := range answers {
		fmt.Println(answer)
	}
}
