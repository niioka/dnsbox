package dns

type DNSRecord struct {
	Id    int64
	Name  string
	RType uint16
}

type DNSRecordStore interface {
	FindByNameAndType(name string, recordType ResourceType) (*DNSRecord, error)
	FindAll() ([]*DNSRecord, error)
}
