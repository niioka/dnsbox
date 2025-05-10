package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type QR int

const (
	QRQuery QR = iota
	QRResponse
)

type Class uint16

const (
	ClassIN Class = 1
)

func (c Class) Bytes() []byte {
	cls := c
	if cls == 0 {
		cls = ClassIN
	}
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(c))
	return buf
}

func (c Class) String() string {
	switch c {
	case ClassIN:
		return "IN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", c)
	}
}

type Opcode int

const (
	OpcodeQuery  Opcode = 0
	OpcodeIQuery Opcode = 1
	OpcodeNotify Opcode = 4
	OpcodeUpdate Opcode = 5
)

const (
	RCodeNoError        = 0
	RCodeFormatError    = 1
	RCodeServerFailure  = 2
	RCodeNameError      = 3
	RCodeNotImplemented = 4
	RCodeRefused        = 5
	RCodeNotAuth        = 8
)

type Question struct {
	Qname  string
	Qtype  ResourceType
	Qclass Class
}

func (q *Question) Bytes() ([]byte, error) {
	result, err := encodeDomain(q.Qname)
	if err != nil {
		return nil, fmt.Errorf("failed to encode domain: %w", err)
	}

	result = append(result, q.Qtype.Bytes()...)
	result = append(result, q.Qclass.Bytes()...)

	return result, nil
}

const (
	OffsetQR      = 7
	OffsetOpcode  = 3
	OffsetAA      = 2
	OffsetTC      = 1
	OffsetRD      = 0
	OffsetRA      = 7
	OffsetAD      = 5
	OffsetCD      = 4
	OffsetRCode   = 0
	BitmaskOpcode = 0x0f
	BitmaskAA     = 0x01
	BitmaskTC     = 0x01
	BitmaskRD     = 0x01
	BitmaskRA     = 0x01
	BitmaskAD     = 0x01
	BitmaskCD     = 0x01
	BitmaskRCode  = 0x07
)

// Packet - See RFC1035 for details.
type Packet struct {
	Id     uint16
	QR     QR
	Opcode Opcode
	// AA - Authoritative Answer
	AA bool
	// TC - Truncated
	TC bool
	// RD - Recursion Desired
	RD bool
	// RA - Recursion Available
	RA bool
	// AD - Authentic Data
	AD bool
	// CD - Checking Disabled
	CD          bool
	RCode       int
	Questions   []*Question
	Answers     []*ResourceRecord
	Authorities []*ResourceRecord
	Additions   []*ResourceRecord
}

func (p *Packet) QuestionCount() uint16 {
	return uint16(len(p.Questions))
}

func (p *Packet) Encode() ([]byte, error) {
	if p == nil {
		return nil, errors.New("packet should not be nil")
	}

	boolToByte := func(b bool) byte {
		if b {
			return 1
		} else {
			return 0
		}
	}

	encodeBase := func() []byte {
		var buf []byte
		buf = binary.BigEndian.AppendUint16(buf, p.Id)

		b1 := func() byte {
			var b byte
			b |= byte((p.QR & 0x01) << OffsetQR)
			b |= byte((p.Opcode & BitmaskOpcode) << OffsetOpcode)
			b |= boolToByte(p.AA) << OffsetAA
			b |= boolToByte(p.TC) << OffsetTC
			b |= boolToByte(p.RD) << OffsetRD
			return b
		}()
		buf = append(buf, b1)

		b2 := func() byte {
			var b byte
			b |= boolToByte(p.RA) << OffsetRA
			b |= boolToByte(p.AD) << OffsetAD
			b |= boolToByte(p.CD) << OffsetCD
			b |= byte((p.RCode & BitmaskRCode) << OffsetRCode)
			return b
		}()
		buf = append(buf, b2)

		buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.Questions)))
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.Answers)))
		// AuthorityCount
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.Authorities)))
		// AdditionalCount
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(p.Additions)))

		return buf
	}

	var buf bytes.Buffer
	buf.Write(encodeBase())

	for _, q := range p.Questions {
		qBuf, err := q.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to encode the question: %w", err)
		}

		buf.Write(qBuf)
	}

	for _, rr := range p.Answers {
		rrBuf, err := rr.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to encode the answer: %w", err)
		}

		buf.Write(rrBuf)
	}

	return buf.Bytes(), nil
}
