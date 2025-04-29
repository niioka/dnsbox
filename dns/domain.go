package dns

import (
	"fmt"
	"strings"
)

const (
	PtrFlag = 0b11000000
	PtrHead = 0b00111111
)

// decodeDomain - バイト配列からドメインをデコードする
func decodeDomain(buf []byte, start int) (string, int, error) {
	pos := start
	stop := len(buf)
	domain, isPtr, err := getPointerString(buf, start, stop)
	if err != nil {
		return "", 0, err
	}
	if isPtr {
		return domain, pos + 2, nil
	}

	for {
		if pos >= stop {
			return "", 0, ErrInvalidDomain
		}
		partLength := int(buf[pos])
		if partLength == 0 {
			pos += 1
			break
		}
		pos += 1
		if pos+partLength > stop {
			return "", 0, ErrInvalidDomain
		}
		part := string(buf[pos : pos+partLength])
		domain += part + "."
		pos += partLength
	}
	return domain, pos, nil
}

func getPointerString(buf []byte, start int, stop int) (s string, isPtr bool, err error) {
	if start+2 > stop {
		return
	}
	// 1文字目がポインターであるか？
	b1 := int(buf[start])
	if (b1 & PtrFlag) != PtrFlag {
		return
	}
	isPtr = true
	b2 := int(buf[start+1])
	// 参照先のインデックス
	idx := (b1&PtrHead)*0x100 + b2
	// 範囲外だった場合はエラー
	if idx >= len(buf) {
		err = ErrInvalidNameIndex
		return
	}
	// ポインターのポインターは一旦許可しない
	if (buf[idx] & PtrFlag) == PtrFlag {
		err = ErrInvalidDomain
		return
	}
	// 参照先を読み込む
	s, _, err = decodeDomain(buf, idx)
	return
}

func encodeDomain(domain string) ([]byte, error) {
	var buf []byte
	if domain == "" || domain == "." {
		return []byte{0}, nil
	}
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, part := range parts {
		partLength := len(part)

		if partLength == 0 || partLength > 63 {
			return nil, fmt.Errorf("invalid part length(part=%q, length=%d): %w", part, partLength, ErrInvalidDomain)
		}

		buf = append(buf, byte(partLength))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0)
	return buf, nil
}
