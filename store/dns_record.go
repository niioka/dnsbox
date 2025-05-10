package store

import (
	"errors"
	"fmt"
	"github.com/niioka/dnsbox/dns"
)

var ErrNotFound = errors.New("not found")

type InMemoryDNSRecordStore struct {
	entities map[int64]dns.DNSRecord
	nextId   int64
}

func (s *InMemoryDNSRecordStore) FindByNameAndType(name string, recordType uint16) (*dns.DNSRecord, error) {
	for _, entity := range s.entities {
		if entity.Name == name {
			return &entity, nil
		}
	}
	return nil, fmt.Errorf("%w: domain=%q", ErrNotFound, name)
}

func (s *InMemoryDNSRecordStore) FindAll() []dns.DNSRecord {
	var results []dns.DNSRecord
	for _, entity := range s.entities {
		results = append(results, entity)
	}
	return results
}
