package dns

import (
	"bytes"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"testing"
)

func TestDecodePacket(t *testing.T) {
	cases := []struct {
		label string
		input []byte
		want  Packet
	}{
		{
			label: "question type=A",
			input: []byte{
				// Header
				// - ID = 340
				0x12, 0x34,
				// - QR = QUESTION OP = QUERY FLAGS = AD
				0b0_0000_001, 0,
				// - QDCOUNT = 1
				0, 1,
				// - ANCOUNT = 0
				0, 0,
				// - NSCOUNT = 0
				0, 0,
				// - ARCOUNT = 0
				0, 0,
				// Question
				// - QNAME
				6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
				// - QTYPE = A
				0, 1,
				// - QCLASS = IN
				0, 1,
			},
			want: Packet{
				Id:    4660,
				QR:    QRQuery,
				RD:    true,
				RCode: RCodeNoError,
				Questions: []*Question{
					{
						Qname:  "google.com.",
						Qtype:  1,
						Qclass: 1,
					},
				},
			},
		},
		{
			label: "response type=A no error",
			input: []byte{
				// Header
				// - ID = 25359
				99, 15,
				// - QR = RESPONSE OP = QUERY FLAGS = RD RA
				0b1_0000_001, 0b1000_0000,
				// - QDCOUNT = 1
				0, 1,
				// - ANCOUNT = 1
				0, 1,
				// - NSCOUNT = 0
				0, 0,
				// - ARCOUNT = 0
				0, 0,
				// Question
				// - QNAME
				6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
				// - QTYPE = A
				0, 1,
				// - QCLASS = IN
				0, 1,
				// Answer
				// - NAME
				6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
				// - TYPE = A
				0, 1,
				// - CLASS = IN
				0, 1,
				// - TTL = 135
				0, 0, 0, 135,
				// - RDATA LENGTH = 4
				0, 4,
				// - RDATA
				142, 250, 196, 110,
			},
			want: Packet{
				Id:     25359,
				QR:     QRResponse,
				Opcode: OpcodeQuery,
				RD:     true,
				RA:     true,
				RCode:  RCodeNoError,
				Questions: []*Question{
					{
						Qname:  "google.com.",
						Qtype:  1,
						Qclass: 1,
					},
				},
				Answers: []*ResourceRecord{
					{
						Name:  "google.com.",
						Class: 1,
						TTL:   135,
						RData: &AData{Address: []byte{142, 250, 196, 110}},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got, err := DecodePacket(tc.input)
			fmt.Printf("%+v\n", got)
			if err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if diff := cmp.Diff(got, &tc.want); diff != "" {
				t.Fatalf("%s: mismatch(-got, +want)\n%v", tc.label, diff)
			}
		})
	}
}

func TestDecodeResourceRecord(t *testing.T) {
	testCases := []struct {
		label string
		input []byte
		want  ResourceRecord
	}{
		{
			label: "A Record",
			input: []byte{
				// NAME
				3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
				// TYPE = A(1)
				0, 1,
				// CLASS
				0, 1,
				// TTL
				0, 0, 0, 135,
				// RDATA LENGTH
				0, 4,
				// RDATA
				142, 250, 196, 110,
			},
			want: ResourceRecord{
				Name:  "www.google.com.",
				Class: 1,
				TTL:   135,
				RData: &AData{Address: []byte{142, 250, 196, 110}},
			},
		},
		{
			label: "TXT Record",
			input: bytes.Join([][]byte{
				{
					// NAME
					6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
					// TYPE = TXT(16)
					00, 16,
					// CLASS = IN(1)
					0, 1,
					// TTL
					0, 0, 0, 135,
					// RDATA LENGTH
					0, 36,
					// RDATA = "v=spf1 include:_spf.google.com ~all"
					35,
				},
				[]byte("v=spf1 include:_spf.google.com ~all"),
			}, nil),
			want: ResourceRecord{
				Name:  "google.com.",
				Class: 1,
				TTL:   135,
				RData: &TXTData{
					Text: "v=spf1 include:_spf.google.com ~all",
				},
			},
		},
		{
			label: "SOA Record",
			input: bytes.Join([][]byte{
				// NAME
				{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
				{
					// TYPE = SOA(6)
					0, 6,
					// CLASS = IN(1)
					0, 1,
					// TTL
					0, 0, 0, 60,
					// RDATA LENGTH
					0, 80,
				},
				// RDATA
				// - MNAME = ns1.google.com.
				{3, 'n', 's', '1', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
				// - RNAME = dns-admin.google.com.
				{9, 'd', 'n', 's', '-', 'a', 'd', 'm', 'i', 'n', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
				// - SERIAL = 765531224
				{45, 161, 20, 88},
				// - REFRESH = 900
				{0, 0, 3, 132},
				// - RETRY = 900
				{0, 0, 3, 132},
				// - EXPIRE = 1800
				{0, 0, 7, 8},
				// - MINIMUM = 60
				{0, 0, 0, 60},
			}, nil),
			want: ResourceRecord{
				Name:  "google.com.",
				Class: 1,
				TTL:   60,
				RData: &SOAData{
					MName:   "ns1.google.com.",
					RName:   "dns-admin.google.com.",
					Serial:  765531224,
					Refresh: 900,
					Retry:   900,
					Expire:  1800,
					Minttl:  60,
				},
			},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			t.Logf("input: %v", len(tc.input))
			record, err := decodeResourceRecord(NewScanner(tc.input))
			if err != nil {
				t.Errorf("decodeResourceRecord %s: unexpected error: %v", tc.label, err)
				return
			}
			if diff := cmp.Diff(record, &tc.want); diff != "" {
				t.Errorf("decodeResourceRecord %s: -got +want\n%v", tc.label, err)
				return
			}
		})
	}
}
