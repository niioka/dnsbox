package dns

import (
	"errors"
	"fmt"
	"strings"
)

const (
	PtrFlag = 0b11000000
	PtrHead = 0b00111111
)

var ErrNotPointer = errors.New("not pointer")
var ErrInvalidDomain = errors.New("invalid domain")

// decodeDomain - バイト配列からドメインをデコードする
func decodeDomain(sc *Scanner) (string, error) {
	var getName func(pos int) (string, int, error)

	visited := make(map[int]struct{})

	getPointer := func(pos int) (int, error) {
		b1, err := sc.PeekAt(pos)
		if err != nil {
			return 0, fmt.Errorf("%w: %+v", ErrInvalidDomain, sc)
		}
		if (b1 & PtrFlag) != PtrFlag {
			return 0, ErrNotPointer
		}

		b2, err := sc.PeekAt(pos + 1)
		if err != nil {
			return 0, ErrInvalidDomain
		}
		// 参照先のインデックス
		idx := (int(b1)&PtrHead)*0x100 + int(b2)
		return idx, nil
	}

	getName = func(pos int) (string, int, error) {
		if _, ok := visited[pos]; ok {
			return "", 0, fmt.Errorf("%w: recursive name: pos=%d", ErrInvalidDomain, pos)
		}
		visited[pos] = struct{}{}
		var domain string
		ptr, err := getPointer(pos)
		if err == nil {
			// compression
			domain, _, err = getName(ptr)
			if err != nil {
				return "", 0, err
			}
			return domain, 2, err
		} else if !errors.Is(err, ErrNotPointer) {
			// invalid format
			return "", 0, err
		}

		for {
			partLength, err := sc.PeekAt(pos)
			if err != nil {
				return "", 0, ErrInvalidDomain
			}
			pos++
			if partLength == 0 {
				break
			}
			part, err := sc.PeekBytesFrom(pos, int(partLength))
			if err != nil {
				return "", 0, fmt.Errorf("%w: %w", ErrInvalidDomain, err)
			}
			domain += string(part) + "."
			pos += int(partLength)
		}
		return domain, len(domain) + 1, nil
	}

	domain, sz, err := getName(sc.Position())
	if err != nil {
		return "", err
	}
	sc.Skip(sz)
	return domain, nil
}

func ValidateDomain(domain string) error {
	if domain == "" || domain == "." {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for i, part := range parts {
		partLength := len(part)
		if partLength == 0 || partLength > 63 {
			return fmt.Errorf("%w: invalid part length(domain=%q)", ErrInvalidDomain, domain)
		}
		for j, c := range part {
			if !isAlnum(c) {
				return fmt.Errorf("%w: invalid character in domain part(domain=%q)", ErrInvalidDomain, domain)
			}
			if (j == 0 || i == len(parts)) && c == '-' {
				return fmt.Errorf("%w: invalid character in domain part(domain=%q)", ErrInvalidDomain, domain)
			}
		}
		// TLD
		if i == len(parts)-1 && partLength < 2 {
			return fmt.Errorf("%w: invalid TLD part length(domain=%q)", ErrInvalidDomain, domain)
		}
	}
	return nil
}

func isAlnum(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func encodeDomain(domain string) ([]byte, error) {
	if domain == "" || domain == "." {
		return []byte{0}, nil
	}

	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	var buf []byte
	for _, label := range labels {
		labelLength := len(label)

		if labelLength == 0 || labelLength > 63 {
			return nil, fmt.Errorf("invalid label length(label=%q, length=%d): %w", label, labelLength, ErrInvalidDomain)
		}

		buf = append(buf, byte(labelLength))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	return buf, nil
}
