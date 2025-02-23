package dns

import (
	"errors"
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
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got, err := DecodePacket(tc.input)
			fmt.Printf("%+v\n", got)
			if err != nil {
				t.Errorf("got %v, want nil", err)
				return
			}
			if !cmp.Equal(got, &tc.want) {
				t.Errorf("want %+v, got %+v", tc.want, got)
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
