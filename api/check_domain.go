package api

import (
	"github.com/niioka/dnsbox/dns"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type QuestionData struct {
	QName       string `json:"qname"`
	QClass      uint16 `json:"qclass"`
	QClassLabel string `json:"qclassLabel"`
	QType       uint16 `json:"qtype"`
	QTypeLabel  string `json:"qtypeLabel"`
}

type ResourceRecordData struct {
	Name       string `json:"name"`
	Class      uint16 `json:"class"`
	ClassLabel string `json:"classLabel"`
	TTL        uint32 `json:"ttl"`
	RData      string `json:"rdata"`
	RDataRaw   []byte `json:"rdataRaw"`
}

type CheckDomainResponse struct {
	ID          uint16                `json:"id"`
	Opcode      uint8                 `json:"opcode"`
	RCode       uint8                 `json:"rcode"`
	Questions   []*QuestionData       `json:"questions"`
	Answers     []*ResourceRecordData `json:"answers"`
	Authorities []*ResourceRecordData `json:"authorities"`
	Additional  []*ResourceRecordData `json:"additional"`
}

type DNSClient interface {
	Resolve(name string, resourceType dns.ResourceType) (*dns.Packet, error)
}

type CheckDomainHandler struct {
	Client DNSClient
}

func (h *CheckDomainHandler) Handle(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")

	if domain == "" {
		sendResponse(w, http.StatusBadRequest, ErrorResponse{
			Message: "domain query parameter is required",
		})
		return
	}

	received, err := h.Client.Resolve(domain, dns.ResourceTypeTXT)
	if err != nil {
		log.Errorf("failed to resolve DNS record: %v", err)
		sendResponse(w, http.StatusInternalServerError, ErrorResponse{
			Message: "failed to resolve DNS record",
		})
		return
	}

	questions := func() []*QuestionData {
		var dest []*QuestionData
		for _, q := range received.Questions {
			dest = append(dest, &QuestionData{
				QName:  q.Qname,
				QClass: uint16(q.Qclass),
				QType:  uint16(q.Qtype),
			})
		}
		return dest
	}()

	answers := func() []*ResourceRecordData {
		var dest []*ResourceRecordData
		for _, a := range received.Answers {
			dest = append(dest, &ResourceRecordData{
				Name:  a.Name,
				TTL:   a.TTL,
				Class: uint16(a.Class),
				RData: a.String(),
			})
		}
		return dest
	}()

	sendResponse(w, http.StatusOK, CheckDomainResponse{
		Opcode:    uint8(received.Opcode),
		RCode:     uint8(received.RCode),
		Questions: questions,
		Answers:   answers,
	})
}
