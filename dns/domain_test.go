package dns

import (
	"bytes"
	"errors"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	// ARRANGE
	cases := []struct {
		label  string
		domain string
		want   error
	}{
		{
			label:  "ok/1",
			domain: "example.com",
		},
		{
			label:  "Err/part-contains-invalid-rune",
			domain: "__.jp",
			want:   ErrInvalidDomain,
		},
		{
			label:  "Err/tld-is-too-short",
			domain: "_.a",
			want:   ErrInvalidDomain,
		},
		{
			label:  "Err/tld-contains-hyphen",
			domain: "x.a-",
			want:   ErrInvalidDomain,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			// ACT
			err := ValidateDomain(tc.domain)

			// ASSERT
			if !errors.Is(err, tc.want) {
				t.Errorf("ValidateDomain(%q) = %v; want %v", tc.domain, err, tc.want)
			}
		})
	}
}

func TestDecodeDomain(t *testing.T) {
	// ARRANGE
	cases := []struct {
		label      string
		input      []byte
		wantDomain string
		wantNext   int
		wantErr    error
	}{
		{
			label:      "ok/google.com",
			input:      []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
			wantDomain: "google.com.",
			wantNext:   12,
		},
		{
			label:   "Err/out-of-bounds",
			input:   []byte{5, 'x'},
			wantErr: ErrInvalidDomain,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			// ACT
			domain, err := decodeDomain(NewScanner(tc.input))

			// ASSERT
			if err != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("Err: want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if domain != tc.wantDomain {
				t.Errorf("domain: want %q, got %q", tc.wantDomain, domain)
				return
			}
		})
	}
}

func TestEncodeDomain(t *testing.T) {
	cases := []struct {
		label      string
		domain     string
		wantDomain []byte
		wantErr    error
	}{
		{
			label:      "ok/google.com.",
			domain:     "google.com.",
			wantDomain: []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			label:      "ok/google.com",
			domain:     "google.com",
			wantDomain: []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			label:      "ok/google.com.",
			domain:     "www.google.com.",
			wantDomain: []byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			label:      "ok/empty-string",
			domain:     "",
			wantDomain: []byte{0},
		},
		{
			label:      "ok/.",
			domain:     ".",
			wantDomain: []byte{0},
		},
		{
			label:   "Err/..example",
			domain:  "..example",
			wantErr: ErrInvalidDomain,
		},
		{
			label:   "Err/very-long-domain",
			domain:  "1234567890123456789012345678901234567890123456789012345678901234.example",
			wantErr: ErrInvalidDomain,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			domain, err := encodeDomain(tc.domain)

			if err != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("Err: want %v, got %v", tc.wantErr, err)
				}
				return
			}

			if !bytes.Equal(domain, tc.wantDomain) {
				t.Errorf("domain: want %q, got %q", tc.wantDomain, domain)
			}
		})
	}
}
