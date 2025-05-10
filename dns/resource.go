package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type ResourceType uint16

const (
	ResourceTypeA     ResourceType = 1
	ResourceTypeNS    ResourceType = 2
	ResourceTypeCNAME ResourceType = 3
	ResourceTypeSOA   ResourceType = 6
	ResourceTypeTXT   ResourceType = 16
	ResourceTypeAAAA  ResourceType = 28
)

func (r ResourceType) Bytes() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(r))
	return buf
}

func (r ResourceType) String() string {
	switch r {
	case ResourceTypeA:
		return "A"
	case ResourceTypeTXT:
		return "TXT"
	case ResourceTypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", r)
	}
}

var resourceNameMap = map[string]ResourceType{
	"A":     ResourceTypeA,
	"NS":    ResourceTypeNS,
	"CNAME": ResourceTypeCNAME,
	"SOA":   ResourceTypeSOA,
	"TXT":   ResourceTypeTXT,
	"AAAA":  ResourceTypeAAAA,
}

func ResourceTypeFromName(name string) (ResourceType, bool) {
	rrType, ok := resourceNameMap[strings.ToUpper(name)]
	return rrType, ok
}

type ResourceRecord struct {
	Name  string
	Class Class
	TTL   uint32
	RData RData
}

func (rr *ResourceRecord) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	name, err := encodeDomain(rr.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to encode domain: %w", err)
	}
	buf.Write(name)
	buf.Write(rr.RData.ResourceType().Bytes())
	buf.Write(rr.Class.Bytes())
	buf.Write(binary.BigEndian.AppendUint32(nil, rr.TTL))
	buf.Write(rr.RData.Bytes())
	return buf.Bytes(), nil
}

func (rr *ResourceRecord) String() string {
	class := func() string {
		if rr.Class == 1 {
			return "IN"
		} else {
			return strconv.Itoa(int(rr.Class))
		}
	}()

	return fmt.Sprintf("%s\t\t%d\t%s\t%s\t%+v", rr.Name, rr.TTL, class, rr.RData.ResourceType(), rr.RData)
}

type RData interface {
	ResourceType() ResourceType
	Bytes() []byte
	String() string
}

type AData struct {
	Address []byte
}

func (d *AData) ResourceType() ResourceType {
	return ResourceTypeA
}

func (d *AData) Bytes() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(d.Address)))
	buf = append(buf, d.Address...)
	return buf
}

func (d *AData) String() string {
	var parts []string
	for _, part := range d.Address {
		parts = append(parts, strconv.Itoa(int(part)))
	}
	return strings.Join(parts, ".")
}

var _ RData = (*AData)(nil)

type SOAData struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

func (s *SOAData) ResourceType() ResourceType {
	return ResourceTypeSOA
}

func (s *SOAData) Bytes() []byte {
	var buf []byte
	mNameSize := len(s.MName)
	buf = append(buf, byte(mNameSize))
	buf = append(buf, []byte(s.MName)...)
	rNameSize := len(s.RName)
	buf = append(buf, byte(rNameSize))
	buf = append(buf, []byte(s.RName)...)
	buf = binary.BigEndian.AppendUint32(buf, s.Serial)
	buf = binary.BigEndian.AppendUint32(buf, s.Refresh)
	buf = binary.BigEndian.AppendUint32(buf, s.Retry)
	buf = binary.BigEndian.AppendUint32(buf, s.Expire)
	buf = binary.BigEndian.AppendUint32(buf, s.Minttl)
	return buf
}

func (s *SOAData) String() string {
	//TODO implement me
	panic("implement me")
}

var _ RData = (*SOAData)(nil)

type TXTData struct {
	Text string
}

func (d *TXTData) ResourceType() ResourceType {
	return ResourceTypeTXT
}

func (d *TXTData) Bytes() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(d.Text)))
	buf = append(buf, []byte(d.Text)...)
	return buf
}

func (d *TXTData) String() string {
	return d.Text
}

var _ RData = (*TXTData)(nil)

type RawData struct {
	Type  ResourceType
	RData []byte
}

func (d *RawData) ResourceType() ResourceType {
	return d.Type
}

func (d *RawData) Bytes() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(d.RData)))
	buf = append(buf, d.RData...)
	return buf
}

func (d *RawData) String() string {
	var byteList []string
	for _, part := range d.RData {
		byteList = append(byteList, strconv.Itoa(int(part)))
	}
	return fmt.Sprintf("[%s]", strings.Join(byteList, ", "))
}

var _ RData = (*RawData)(nil)
