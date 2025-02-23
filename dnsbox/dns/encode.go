package dns

import (
	"encoding/binary"
	"strings"
)

func EncodePacket(packet *Packet) ([]byte, error) {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, packet.Id)

	var b1 byte
	b1 |= byte((packet.Qr & 0x01) << QR_OFFSET)
	b1 |= byte((packet.Opcode & OPCODE_BITMASK) << OPCODE_OFFSET)
	b1 |= boolToByte(packet.IsAuthoritativeAnswer) << AA_OFFSET
	b1 |= boolToByte(packet.IsTruncated) << TC_OFFSET
	b1 |= boolToByte(packet.IsRecursionDesired) << RD_OFFSET
	buf = append(buf, b1)

	var b2 byte
	b2 |= boolToByte(packet.IsRecursionAvailable) << RA_OFFSET
	b2 |= boolToByte(packet.IsAuthenticData) << AD_OFFSET
	b2 |= boolToByte(packet.IsCheckingDisabled) << CD_OFFSET
	b2 |= byte((packet.Rcode & RCODE_BITMASK) << RCODE_OFFSET)
	buf = append(buf, b2)

	buf = binary.BigEndian.AppendUint16(buf, packet.QuestionCount)
	buf = binary.BigEndian.AppendUint16(buf, packet.AnswerCount)
	buf = binary.BigEndian.AppendUint16(buf, packet.AuthorityCount)
	buf = binary.BigEndian.AppendUint16(buf, packet.AdditionalCount)

	for _, q := range packet.Questions {
		qBuf, err := encodeQuestion(q)
		if err != nil {
			return nil, err
		}
		buf = append(buf, qBuf...)
	}

	return buf, nil
}

func encodeQuestion(q *Question) ([]byte, error) {
	var buf, result []byte
	var err error

	buf, err = encodeDomain(q.Qname)
	if err != nil {
		return nil, err
	}
	result = append(result, buf...)

	result = binary.BigEndian.AppendUint16(result, q.Qtype)
	result = binary.BigEndian.AppendUint16(result, q.Qclass)

	return result, nil
}

func encodeDomain(domain string) ([]byte, error) {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		partLength := len(part)
		if partLength == 0 || partLength > 255 {
			return nil, ErrInvalidDomain
		}
		buf = append(buf, byte(partLength))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0)
	return buf, nil
}

func boolToByte(b bool) byte {
	if b {
		return 1
	} else {
		return 0
	}
}
