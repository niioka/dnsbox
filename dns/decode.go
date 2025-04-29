package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const PacketBaseLength = 12

var ErrPacketTooShort = errors.New("packet too short")
var ErrInvalidNameIndex = errors.New("invalid name index")

type PacketDecoder struct {
	pos int
	buf []byte
	err error
}

// DecodePacket - DNSパケットをバイト配列から取得する
func (pd *PacketDecoder) DecodePacket(buf []byte) (*Packet, error) {
	if len(buf) < PacketBaseLength {
		return nil, fmt.Errorf("invalid packet: %w", ErrInvalidDomain)
	}
	pd.pos = 0
	pd.buf = buf
	pd.err = nil

	id := pd.decodeUint16()

	b1 := pd.decodeByte()
	qr := QR((b1 >> QR_OFFSET) & 0x01)
	opcode := Opcode((b1 >> OPCODE_OFFSET) & OPCODE_BITMASK)
	isAuthoritativeAnswer := ((b1 >> AA_OFFSET) & AA_BITMASK) != 0
	isTruncated := ((b1 >> TC_OFFSET) & TC_BITMASK) != 0
	isRecursionDesired := ((b1 >> RD_OFFSET) & RD_BITMASK) != 0

	b2 := pd.decodeByte()
	isRecursionAvailable := ((b2 >> RA_OFFSET) & RA_BITMASK) != 0
	isAuthenticData := ((b2 >> AD_OFFSET) & AD_BITMASK) != 0
	isCheckingDisabled := ((b2 >> CD_OFFSET) & CD_BITMASK) != 0
	rcode := int((b2 >> RCODE_OFFSET) & RCODE_BITMASK)

	qdCount := pd.decodeUint16()
	anCount := pd.decodeUint16()
	nsCount := pd.decodeUint16()
	arCount := pd.decodeUint16()
	if pd.err != nil {
		return nil, pd.err
	}

	questions := pd.decodeQuestions(qdCount)
	if pd.err != nil {
		return nil, pd.err
	}

	answers := pd.decodeResourceRecords(anCount)

	return &Packet{
		Id:                    id,
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
		Answers:               answers,
	}, nil
}

func (pd *PacketDecoder) decodeUint32() uint32 {
	if pd.err != nil {
		return 0
	}
	if pd.pos+4 > len(pd.buf) {
		pd.err = ErrPacketTooShort
		return 0
	}
	n := binary.BigEndian.Uint32(pd.buf[pd.pos : pd.pos+4])
	pd.pos += 4
	return n
}

func (pd *PacketDecoder) decodeUint16() uint16 {
	if pd.err != nil {
		return 0
	}
	if pd.pos+2 > len(pd.buf) {
		pd.err = ErrPacketTooShort
		return 0
	}
	n := binary.BigEndian.Uint16(pd.buf[pd.pos : pd.pos+2])
	pd.pos += 2
	return n
}

func (pd *PacketDecoder) decodeByte() byte {
	if pd.err != nil {
		return 0
	}
	if pd.pos >= len(pd.buf) {
		pd.err = ErrPacketTooShort
		return 0
	}
	b := pd.buf[pd.pos]
	pd.pos++
	return b
}

func (pd *PacketDecoder) peekByte() (byte, error) {
	if pd.err != nil {
		return 0, pd.err
	}
	if pd.pos >= len(pd.buf) {
		pd.err = ErrPacketTooShort
		return 0, pd.err
	}
	return pd.buf[pd.pos], nil
}

func (pd *PacketDecoder) decodeQuestions(qdCount uint16) []*Question {
	if pd.err != nil {
		return nil
	}
	var questions []*Question
	for i := 0; i < int(qdCount); i++ {
		question := pd.decodeQuestion()
		if question == nil {
			return nil
		}

		questions = append(questions, question)
	}
	return questions
}

func (pd *PacketDecoder) decodeQuestion() *Question {
	if pd.err != nil {
		return nil
	}

	qname, pos, err := decodeDomain(pd.buf, pd.pos)
	if err != nil {
		pd.err = fmt.Errorf("failed to decode domain: %w", err)
		return nil
	}
	pd.pos = pos

	qtype := pd.decodeUint16()
	qclass := pd.decodeUint16()

	return &Question{
		Qname:  qname,
		Qtype:  qtype,
		Qclass: qclass,
	}
}

func (pd *PacketDecoder) decodeResourceRecords(recordCount uint16) []*ResourceRecord {
	if pd.err != nil {
		return nil
	}
	var records []*ResourceRecord
	for i := 0; i < int(recordCount); i++ {
		record := pd.decodeResourceRecord()
		if record == nil {
			return nil
		}
		records = append(records, record)
	}
	return records
}

func (pd *PacketDecoder) decodeResourceRecord() *ResourceRecord {
	if pd.err != nil {
		return nil
	}
	name, next, err := decodeDomain(pd.buf, pd.pos)
	if err != nil {
		pd.err = err
		return nil
	}
	pd.pos = next

	rtype := pd.decodeUint16()
	rclass := pd.decodeUint16()
	ttl := pd.decodeUint32()
	rdata := pd.decodeSizedBytes()
	if pd.err != nil {
		return nil
	}

	return &ResourceRecord{
		Name:  name,
		Type:  rtype,
		Class: rclass,
		TTL:   ttl,
		RData: rdata,
	}
}

func (pd *PacketDecoder) decodeSizedBytes() []byte {
	if pd.err != nil {
		return nil
	}
	length := int(pd.decodeUint16())
	if pd.err != nil {
		return nil
	}
	if length == 0 {
		return []byte{}
	}
	if pd.pos+length > len(pd.buf) {
		pd.err = ErrPacketTooShort
		return nil
	}
	return pd.buf[pd.pos : pd.pos+length]
}
