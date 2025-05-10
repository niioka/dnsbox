package api

import (
	"encoding/json"
	"errors"
	"github.com/google/go-cmp/cmp"
	"github.com/niioka/dnsbox/dns"
	"net/http"
	"net/http/httptest"
	"testing"
)

type StubDNSClient struct {
	ResolveFunc func(name string, resourceType dns.ResourceType) (*dns.Packet, error)
}

func (c StubDNSClient) Resolve(name string, resourceType dns.ResourceType) (*dns.Packet, error) {
	if c.ResolveFunc == nil {
		return nil, errors.New("ResolveFunc should not be nil")
	}
	return c.ResolveFunc(name, resourceType)
}

var _ DNSClient = &StubDNSClient{}

func TestTestDomainHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := StubDNSClient{
			ResolveFunc: func(name string, resourceType dns.ResourceType) (*dns.Packet, error) {
				return &dns.Packet{
					Id: 1234,
					Questions: []*dns.Question{
						{
							Qname:  "www.google.com.",
							Qclass: dns.ClassIN,
							Qtype:  dns.ResourceTypeA,
						},
					},
				}, nil
			},
		}
		handler := CheckDomainHandler{
			Client: client,
		}
		req := httptest.NewRequest(http.MethodGet, "/api/test?domain=www.google.com", nil)
		w := httptest.NewRecorder()
		// ACT
		handler.Handle(w, req)

		// ASSERT
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("wrong status code: got %v want %v", res.StatusCode, http.StatusOK)
		}

		var body CheckDomainResponse
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		wantBody := CheckDomainResponse{
			Questions: []*QuestionData{
				{
					QName:  "www.google.com.",
					QClass: 1,
					QType:  1,
				},
			},
		}
		if diff := cmp.Diff(body, wantBody); diff != "" {
			t.Fatalf("body does not match (-got, +want)\n%v", diff)
		}
	})

	t.Run("query parameter is missing", func(t *testing.T) {
		handler := CheckDomainHandler{}
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		// ACT
		handler.Handle(w, req)

		// ASSERT
		res := w.Result()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("status: want %d, got %d", http.StatusBadRequest, res.StatusCode)
		}

		var errResp ErrorResponse
		if err := json.NewDecoder(res.Body).Decode(&errResp); err != nil {
			t.Error(err)
		}

		want := ErrorResponse{
			Message: "domain query parameter is required",
		}
		if diff := cmp.Diff(errResp, want); diff != "" {
			t.Errorf("response body does not match(-got, +want)\n%v", diff)
		}
	})

}
