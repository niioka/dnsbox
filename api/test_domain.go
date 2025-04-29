package api

import (
	"encoding/json"
	"github.com/niioka/dnsbox/dns"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type TestDomainResponse struct {
	Domain string `json:"domain"`
	Record string `json:"record"`
}

type DNSClient interface {
	Resolve(question *dns.Question) ([]*dns.ResourceRecord, error)
}

type TestDomainHandler struct {
	Client DNSClient
}

func (h *TestDomainHandler) Handle(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")

	if domain == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		resp := struct {
			Message string `json:"message"`
		}{
			Message: "domain query parameter is required",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	record, err := h.Client.Resolve(&dns.Question{
		Qname:  domain,
		Qtype:  dns.TypeTXT,
		Qclass: 1,
	})
	if err != nil {
		log.Errorf("failed to resolve DNS record: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		resp := struct {
			Message string `json:"message"`
		}{
			Message: "domain query parameter is required",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if len(record) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		resp := struct {
			Message string `json:"message"`
		}{
			Message: "DNS record does not found",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := TestDomainResponse{
		Domain: domain,
		Record: record[0].String(),
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Errorf("failed to encode JSON: %v", err)
	}
}
