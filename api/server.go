package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/niioka/dnsbox/dns"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func Start() error {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	testDomainHandler := TestDomainHandler{
		Client: dns.NewClient("8.8.8.8"),
	}

	r.Get("/api/test", testDomainHandler.Handle)

	log.Infof("Start http server on port %d", 8080)
	return http.ListenAndServe(":8080", r)
}
