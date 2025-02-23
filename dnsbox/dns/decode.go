package dns

import (
	"encoding/binary"
	"errors"
)

const PacketBaseLength = 12

var ErrInvalidDomain = errors.New("invalid domain")
var ErrPacketTooShort = errors.New("packet too short")

func DecodePacket(buf []byte) (*Packet, error) {
	if len(buf) < PacketBaseLength {
		return nil, errors.New("invalid packet")
	}
	qr := QR((buf[2] >> QR_OFFSET) & 0x01)
	opcode := Opcode((buf[2] >> OPCODE_OFFSET) & OPCODE_BITMASK)
	isAuthoritativeAnswer := ((buf[2] >> AA_OFFSET) & AA_BITMASK) != 0
	isTruncated := ((buf[2] >> TC_OFFSET) & TC_BITMASK) != 0
	isRecursionDesired := ((buf[2] >> RD_OFFSET) & RD_BITMASK) != 0
	isRecursionAvailable := ((buf[3] >> RA_OFFSET) & RA_BITMASK) != 0
	isAuthenticData := ((buf[3] >> AD_OFFSET) & AD_BITMASK) != 0
	isCheckingDisabled := ((buf[3] >> CD_OFFSET) & CD_BITMASK) != 0
	rcode := int((buf[3] >> RCODE_OFFSET) & RCODE_BITMASK)
	qdCount := binary.BigEndian.Uint16(buf[4:6])
	anCount := binary.BigEndian.Uint16(buf[6:8])
	nsCount := binary.BigEndian.Uint16(buf[8:10])
	arCount := binary.BigEndian.Uint16(buf[10:12])

	var questions []*Question
	pos := PacketBaseLength
	for i := 0; i < int(qdCount); i++ {
		question, err := decodeQuestion(buf, pos)
		if err != nil {
			return nil, err
		}
		questions = append(questions, question)
	}

	return &Packet{
		Id:                    binary.BigEndian.Uint16(buf[0:2]),
		Qr:                    qr,
		Opcode:                opcode,
		IsAuthoritativeAnswer: isAuthoritativeAnswer,
		IsTruncated:           isTruncated,
		IsRecursionDesired:    isRecursionDesired,
		IsRecursionAvailable:  isRecursionAvailable,
		IsAuthenticData:       isAuthenticData,
		IsCheckingDisabled:    isCheckingDisabled,
		Rcode:                 rcode,
		QuestionCount:         qdCount,
		AnswerCount:           anCount,
		AuthorityCount:        nsCount,
		AdditionalCount:       arCount,
		Questions:             questions,
	}, nil
}

func decodeDomain(buf []byte, start int) (string, int, error) {
	pos := start
	stop := len(buf)
	var domain string
	for {
		if pos >= stop {
			return "", -1, ErrInvalidDomain
		}
		partLength := int(buf[pos])
		if partLength == 0 {
			pos += 1
			break
		}
		pos += 1
		if pos+partLength > stop {
			return "", -1, ErrInvalidDomain
		}
		part := string(buf[pos : pos+partLength])
		domain += part + "."
		pos += partLength
	}
	return domain, pos, nil
}

func decodeQuestion(buf []byte, start int) (*Question, error) {
	stop := len(buf)
	qname, pos, err := decodeDomain(buf, start)
	if err != nil {
		return nil, err
	}
	if pos+4 > stop {
		return nil, ErrPacketTooShort
	}
	qtype := binary.BigEndian.Uint16(buf[pos : pos+2])
	qclass := binary.BigEndian.Uint16(buf[pos+2 : pos+4])
	return &Question{
		Qname:  qname,
		Qtype:  qtype,
		Qclass: qclass,
	}, nil
}
