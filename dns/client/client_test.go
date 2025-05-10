package client

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/niioka/dnsbox/dns"
	"net"
	"testing"
)

func TestClient_Resolve(t *testing.T) {
	// ARRANGE
	clientConn, serverConn := net.Pipe()

	defer clientConn.Close()
	defer serverConn.Close()

	// emulate the server connection
	go mockServer(t, serverConn)

	c := New(Config{
		Server:  "8.8.8.8",
		Port:    80,
		Verbose: true,
		DialFunc: func(network string, address string) (net.Conn, error) {
			return clientConn, nil
		},
	})

	// ACT
	received, err := c.Resolve("google.com", dns.ResourceTypeA)

	// ASSERT
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	want := &dns.Packet{
		QR:     dns.QRResponse,
		Opcode: dns.OpcodeQuery,
		RD:     true,
		Questions: []*dns.Question{
			{
				Qname:  "google.com.",
				Qtype:  dns.ResourceTypeA,
				Qclass: dns.ClassIN,
			},
		},
		Answers: []*dns.ResourceRecord{
			{
				Name:  "google.com.",
				Class: dns.ClassIN,
				TTL:   3600,
				RData: &dns.AData{
					Address: []byte{192, 168, 1, 1},
				},
			},
		},
	}
	if diff := cmp.Diff(want, received, cmpopts.IgnoreFields(dns.Packet{}, "Id")); diff != "" {
		t.Fatalf("Resolve: mismatch(-want, +got):\n%s", diff)
	}
}

func mockServer(t *testing.T, serverConn net.Conn) {
	defer serverConn.Close()

	var readBuf [1024]byte
	n, err := serverConn.Read(readBuf[:])
	if err != nil {
		t.Errorf("failed to read the packet: %v", err)
		return
	}
	readPacket, err := dns.DecodePacket(readBuf[:n])
	if err != nil {
		t.Errorf("failed to decode the packet: %v", err)
		return
	}
	answers := []*dns.ResourceRecord{
		{
			Name:  "google.com.",
			Class: dns.ClassIN,
			TTL:   3600,
			RData: &dns.AData{
				Address: []byte{192, 168, 1, 1},
			},
		},
	}
	writePacket := &dns.Packet{
		Id:        readPacket.Id,
		Opcode:    readPacket.Opcode,
		QR:        dns.QRResponse,
		AA:        readPacket.AA,
		TC:        readPacket.TC,
		RD:        readPacket.RD,
		RA:        readPacket.RA,
		RCode:     dns.RCodeNoError,
		Questions: readPacket.Questions,
		Answers:   answers,
		Additions: readPacket.Additions,
	}
	writeBuf, err := writePacket.Encode()
	if err != nil {
		t.Errorf("failed to encode the packet: %v", err)
		return
	}
	t.Logf("writeBuf: %v", writeBuf)
	_, _ = serverConn.Write(writeBuf)

}
