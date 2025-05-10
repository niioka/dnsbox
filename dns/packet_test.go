package dns

import (
	"bytes"
	"testing"
)

func TestPacket_Encode_success(t *testing.T) {
	cases := []struct {
		label string
		input *Packet
		want  []byte
	}{
		{
			label: "question",
			input: &Packet{
				Id:    4660,
				QR:    QRQuery,
				AA:    false,
				TC:    false,
				RD:    true,
				RCode: 0,
				Questions: []*Question{
					{
						Qname:  "google.com",
						Qtype:  1,
						Qclass: 1,
					},
				},
			},
			want: []byte{
				0x12, 0x34, 1, 0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			got, err := tc.input.Encode()
			if err != nil {
				t.Errorf("EncodePacket(%v) failed: %v", tc.input, err)
				return
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("want %+v, got %+v", tc.want, got)
			}
		})
	}
}
