package main

import (
	"dnsbox/dnsbox/dns"
	"fmt"
)

func main() {
	client := dns.NewClient("8.8.8.8")
	answers, err := client.ResolveTXT("_dmarc.google.com")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(";; ANSWER SECTION:")
	for _, answer := range answers {
		fmt.Println(answer)
	}
}
