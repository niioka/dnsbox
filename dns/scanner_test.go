package dns

import (
	"fmt"
	"testing"
)

func TestScannerReadBytes(t *testing.T) {
	tests := []struct {
		input  []byte
		offset int
		length int
		want   string
	}{
		{
			input:  []byte("hello, world"),
			length: 5,
			want:   "hello",
		},
		{
			input:  []byte("hello, world"),
			length: 12,
			want:   "hello, world",
		},
		{
			input:  []byte("hello, world"),
			offset: 7,
			length: 5,
			want:   "world",
		},
	}

	for i, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("ReadBytes[%d]", i), func(t *testing.T) {
			sc := NewScanner(tc.input)
			if tc.offset > 0 {
				sc.Skip(tc.offset)
			}
			buf, err := sc.ReadBytes(tc.length)
			if err != nil {
				t.Errorf("failed to read bytes: %v", err)
				return
			}
			if string(buf) != tc.want {
				t.Errorf("want %q, got %q", tc.want, string(buf))
			}
		})
	}
}
