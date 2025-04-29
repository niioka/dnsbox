package main

import (
	"github.com/niioka/dnsbox/api"
	log "github.com/sirupsen/logrus"
)

func main() {
	err := api.Start()
	if err != nil {
		log.Fatal(err)
	}
}
