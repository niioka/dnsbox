package dns

import (
	"fmt"
	"strconv"
	"strings"
)

type QR int

type Opcode int
type ResourceType int

const (
	QRQuery QR = iota
	QRResponse
)

const (
	_                 Opcode = iota
	OpcodeNormalQuery        = 1
	OpcodeNotify             = 4
	OpcodeUpdate             = 5
)

const (
	QR_OFFSET      = 7
	OPCODE_OFFSET  = 3
	OPCODE_BITMASK = 0x0f
	AA_OFFSET      = 2
	AA_BITMASK     = 0x01
	TC_OFFSET      = 1
	TC_BITMASK     = 0x01
	RD_OFFSET      = 0
	RD_BITMASK     = 0x01
	RA_OFFSET      = 7
	RA_BITMASK     = 0x01
	AD_OFFSET      = 5
	AD_BITMASK     = 0x01
	CD_OFFSET      = 4
	CD_BITMASK     = 0x01
	RCODE_OFFSET   = 0
	RCODE_BITMASK  = 0x07
)

const (
	_       ResourceType = iota
	TypeA                = 1
	TypeTXT              = 16
)

type Question struct {
	Qname  string
	Qtype  uint16
	Qclass uint16
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

type Packet struct {
	Id     uint16
	Qr     QR
	Opcode Opcode
	// AA
	IsAuthoritativeAnswer bool
	// TC
	IsTruncated bool
	// RD
	IsRecursionDesired bool
	// RA
	IsRecursionAvailable bool
	// AD
	IsAuthenticData bool
	// CD
	IsCheckingDisabled bool
	Rcode              int
	QuestionCount      uint16
	AnswerCount        uint16
	AuthorityCount     uint16
	AdditionalCount    uint16
	Questions          []*Question
	Answers            []*ResourceRecord
}

func (rr *ResourceRecord) String() string {
	var rType string
	var rData strings.Builder
	if rr.Type == TypeA {
		rType = "A"
		for i, part := range rr.RData {
			if i > 0 {
				rData.WriteByte('.')
			}
			rData.WriteString(strconv.Itoa(int(part)))
		}
	} else if rr.Type == TypeTXT {
		rType = "TXT"
		rData.Write(rr.RData)
	} else {
		rType = fmt.Sprintf("%d", rr.Type)
		rData.WriteByte('[')
		for i, part := range rr.RData {
			if i > 0 {
				rData.WriteString(", ")
			}
			rData.WriteString(strconv.Itoa(int(part)))
		}
		rData.WriteByte(']')
	}

	var class string
	if rr.Class == 1 {
		class = "IN"
	} else {
		class = strconv.Itoa(int(rr.Class))
	}

	return fmt.Sprintf("%s\t\t%d\t%s\t%s\t%s", rr.Name, rr.TTL, class, rType, rData.String())
}
