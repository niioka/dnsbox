package main

import (
	"flag"
	"fmt"
	"github.com/niioka/dnsbox/dns"
	"github.com/niioka/dnsbox/dns/client"
)

type Args struct {
	DNSServer string
	Name      string
	RRType    dns.ResourceType
}

func main() {

	args, err := parseArgs()
	if err != nil {
		fmt.Printf("failed to parse args: %v", err)
		return
	}

	dnsClient := client.New(client.Config{
		Server: args.DNSServer,
	})

	received, err := dnsClient.Resolve(args.Name, args.RRType)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(";; ANSWER SECTION:")
	for _, answer := range received.Answers {
		fmt.Println(answer)
	}
}

func parseArgs() (*Args, error) {
	result := Args{}
	flag.StringVar(&result.DNSServer, "dns-server", "8.8.8.8", "DNS Server")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		return nil, fmt.Errorf("domain is required")
	}

	result.Name = args[0]
	if len(args) >= 2 {
		rrType, ok := dns.ResourceTypeFromName(args[1])
		if !ok {
			return nil, fmt.Errorf("unsupported RRType: %s", args[1])
		}
		result.RRType = rrType
	} else {
		result.RRType = dns.ResourceTypeA
	}
	return &result, nil
}
