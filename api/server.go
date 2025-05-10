package api

import (
	"context"
	"github.com/niioka/dnsbox/dns/client"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	httpServer http.Server
}

func New() *Server {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	client := client.New(client.Config{
		Server:  "8.8.8.8",
		Verbose: true,
	})

	testDomainHandler := CheckDomainHandler{
		Client: client,
	}

	r.Get("/api/check", testDomainHandler.Handle)

	return &Server{
		httpServer: http.Server{
			Addr:    ":8080",
			Handler: r,
		},
	}
}

func (s *Server) Start() error {
	log.Infof("Start API server on %s...", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Stop() error {
	log.Infof("Stutting down API server on %s...", s.httpServer.Addr)
	return s.httpServer.Shutdown(context.Background())
}
