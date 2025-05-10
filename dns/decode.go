package dns

import (
	"fmt"
)

const PacketBaseLength = 12

type PacketDecodeError struct {
	Err   error
	Field string
}

func (e *PacketDecodeError) Error() string {
	return fmt.Sprintf("packet decode error (field=%q): %v", e.Field, e.Err)
}

func (e *PacketDecodeError) Unwrap() error {
	return e.Err
}

type PacketDecoder struct {
	// pos は現在の解析位置
	pos int
	buf []byte
	err error
}

// DecodePacket - DNSパケットをバイト配列から取得する
func DecodePacket(buf []byte) (*Packet, error) {
	sc := NewScanner(buf)

	id, err := sc.ReadUint16()
	if err != nil {
		return nil, &PacketDecodeError{
			Err:   err,
			Field: "ID",
		}
	}
	b1, err := sc.ReadByte()
	if err != nil {
		return nil, &PacketDecodeError{
			Err:   err,
			Field: "FLAGS[0]",
		}
	}
	qr := QR((b1 >> OffsetQR) & 0x01)
	opcode := Opcode((b1 >> OffsetOpcode) & BitmaskOpcode)
	aa := ((b1 >> OffsetAA) & BitmaskAA) != 0
	tc := ((b1 >> OffsetTC) & BitmaskTC) != 0
	rd := ((b1 >> OffsetRD) & BitmaskRD) != 0

	b2, err := sc.ReadByte()
	if err != nil {
		return nil, &PacketDecodeError{
			Err:   err,
			Field: "FLAGS[1]",
		}
	}
	isRecursionAvailable := ((b2 >> OffsetRA) & BitmaskRA) != 0
	isAuthenticData := ((b2 >> OffsetAD) & BitmaskAD) != 0
	isCheckingDisabled := ((b2 >> OffsetCD) & BitmaskCD) != 0
	rcode := int((b2 >> OffsetRCode) & BitmaskRCode)

	qdCount, err := sc.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("decode packet: qdCount: %w", err)
	}
	anCount, err := sc.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("decode packet: anCount: %w", err)
	}
	nsCount, err := sc.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("decode packet: nsCount: %w", err)
	}
	arCount, err := sc.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("decode packet: arCount: %w", err)
	}

	questions, err := decodeQuestions(sc, qdCount)
	if err != nil {
		return nil, fmt.Errorf("decode packet: questions: %w", err)
	}
	answers, err := decodeResourceRecords(sc, anCount)
	if err != nil {
		return nil, fmt.Errorf("decode packet: answers: %w", err)
	}
	authorities, err := decodeResourceRecords(sc, nsCount)
	if err != nil {
		return nil, &PacketDecodeError{
			Err:   err,
			Field: "AUTHORITY RRs",
		}
	}
	additions, err := decodeResourceRecords(sc, arCount)
	if err != nil {
		return nil, &PacketDecodeError{
			Err:   err,
			Field: "ADDITIONAL RRs",
		}
	}

	return &Packet{
		Id:          id,
		QR:          qr,
		Opcode:      opcode,
		AA:          aa,
		TC:          tc,
		RD:          rd,
		RA:          isRecursionAvailable,
		AD:          isAuthenticData,
		CD:          isCheckingDisabled,
		RCode:       rcode,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additions:   additions,
	}, nil
}

func decodeQuestions(sc *Scanner, qdCount uint16) ([]*Question, error) {
	var questions []*Question
	for i := 0; i < int(qdCount); i++ {
		question, err := decodeQuestion(sc)
		if err != nil {
			return nil, err
		}

		questions = append(questions, question)
	}
	return questions, nil
}

func decodeQuestion(sc *Scanner) (*Question, error) {
	qname, err := decodeDomain(sc)
	if err != nil {
		return nil, err
	}

	qtype, err := sc.ReadUint16()
	if err != nil {
		return nil, err
	}
	qclass, err := sc.ReadUint16()
	if err != nil {
		return nil, err
	}

	return &Question{
		Qname:  qname,
		Qtype:  ResourceType(qtype),
		Qclass: Class(qclass),
	}, nil
}

func decodeResourceRecords(sc *Scanner, recordCount uint16) ([]*ResourceRecord, error) {
	var records []*ResourceRecord
	for i := 0; i < int(recordCount); i++ {
		record, err := decodeResourceRecord(sc)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func decodeResourceRecord(sc *Scanner) (*ResourceRecord, error) {
	name, err := decodeDomain(sc)
	if err != nil {
		return nil, err
	}

	rrType, err := sc.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("TYPE: %w", err)
	}
	class, err := sc.ReadUint16()
	if err != nil {
		return nil, err
	}

	ttl, err := sc.ReadUint32()
	if err != nil {
		return nil, err
	}

	rdLength, err := sc.ReadUint16()
	if err != nil {
		return nil, err
	}

	rdata, err := decodeRData(sc, ResourceType(rrType), rdLength)
	if err != nil {
		return nil, fmt.Errorf("RDATA: %w", err)
	}

	return &ResourceRecord{
		Name:  name,
		Class: Class(class),
		TTL:   ttl,
		RData: rdata,
	}, nil
}

func decodeRData(sc *Scanner, rrType ResourceType, rdLength uint16) (RData, error) {
	decodeString := func() ([]byte, error) {
		size, err := sc.ReadByte()
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		return sc.ReadBytes(int(size))
	}

	if rrType == ResourceTypeA {
		addr, err := sc.ReadBytes(4)
		if err != nil {
			return nil, err
		}
		return &AData{
			Address: addr,
		}, nil
	} else if rrType == ResourceTypeTXT {
		nRead := uint16(0)
		buf := make([]byte, 0, rdLength)
		for nRead < rdLength {
			bs, err := decodeString()
			if err != nil {
				return nil, err
			}
			nRead += uint16(len(bs)) + 1
			buf = append(buf, bs...)
		}
		return &TXTData{
			Text: string(buf),
		}, nil
	} else if rrType == ResourceTypeSOA {
		mname, err := decodeDomain(sc)
		if err != nil {
			return nil, err
		}
		rname, err := decodeDomain(sc)
		if err != nil {
			return nil, err
		}
		serial, err := sc.ReadUint32()
		if err != nil {
			return nil, err
		}
		refresh, err := sc.ReadUint32()
		if err != nil {
			return nil, err
		}
		retry, err := sc.ReadUint32()
		if err != nil {
			return nil, err
		}
		expire, err := sc.ReadUint32()
		if err != nil {
			return nil, err
		}
		minimum, err := sc.ReadUint32()
		if err != nil {
			return nil, err
		}
		return &SOAData{
			MName:   mname,
			RName:   rname,
			Serial:  serial,
			Refresh: refresh,
			Retry:   retry,
			Expire:  expire,
			Minttl:  minimum,
		}, nil
	} else {
		return nil, fmt.Errorf("invalid resource type (type=%d)", rrType)
	}
}
