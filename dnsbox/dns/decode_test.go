package dns

import (
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"testing"
)

func TestPacketDecoder_DecodePacket(t *testing.T) {
	cases := []struct {
		label string
		input []byte
		want  Packet
	}{
		{
			label: "question type=A",
			input: []byte{
				0x12, 0x34, 0, 0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
			},
			want: Packet{
				Id:                    4660,
				Qr:                    QRQuery,
				IsAuthoritativeAnswer: false,
				IsTruncated:           false,
				Rcode:                 0,
				QuestionCount:         1,
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
			label: "response type=A",
			input: []byte{
				99, 15, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0,
				// Question
				6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1,
				// Answer
				192, 12, 0, 1, 0, 1, 0, 0, 0, 135, 0, 4, 142, 250, 196, 110,
			},
			want: Packet{
				Id:                    25359,
				Qr:                    QRResponse,
				Opcode:                0,
				IsAuthoritativeAnswer: false,
				IsTruncated:           false,
				IsRecursionDesired:    true,
				IsRecursionAvailable:  true,
				QuestionCount:         1,
				AnswerCount:           1,
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
						Type:  1,
						Class: 1,
						TTL:   135,
						RData: []byte{142, 250, 196, 110},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			var pd PacketDecoder
			got, err := pd.DecodePacket(tc.input)
			fmt.Printf("%+v\n", got)
			if err != nil {
				t.Errorf("got %v, want nil", err)
				return
			}
			if !cmp.Equal(got, &tc.want) {
				t.Errorf("want %s, got %s", spew.Sdump(tc.want), spew.Sdump(got))
			}
		})
	}
}

func TestDecodeDomain(t *testing.T) {
	cases := []struct {
		label      string
		input      []byte
		wantDomain string
		wantNext   int
		wantErr    error
	}{
		{
			label:      "google.com",
			input:      []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantDomain: "google.com.",
			wantNext:   12,
			wantErr:    nil,
		},
		{
			label:      "out of bounds",
			input:      []byte{5, 'x'},
			wantDomain: "",
			wantNext:   -1,
			wantErr:    ErrInvalidDomain,
		},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			gotDomain, gotNext, gotErr := decodeDomain(tc.input, 0)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Errorf("want %v, got %v", tc.wantErr, gotErr)
				return
			}
			if gotDomain != tc.wantDomain {
				t.Errorf("want %s, got %s", tc.wantDomain, gotDomain)
				return
			}
			if gotNext != tc.wantNext {
				t.Errorf("want %d, got %d", tc.wantNext, gotNext)
				return
			}
		})
	}
}
