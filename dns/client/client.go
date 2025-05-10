package client

import (
	"fmt"
	"github.com/niioka/dnsbox/dns"
	"github.com/niioka/dnsbox/util"
	log "github.com/sirupsen/logrus"
	"math"
	"math/rand"
	"net"
)

type Client struct {
	server   string
	port     int
	verbose  bool
	dialFunc func(string, string) (net.Conn, error)
}

type Config struct {
	Server   string
	Port     int
	Verbose  bool
	DialFunc func(string, string) (net.Conn, error)
}

func New(config Config) *Client {
	if config.Server == "" {
		config.Server = "8.8.8.8"
	}
	if config.Port == 0 {
		config.Port = 53
	}
	if config.DialFunc == nil {
		config.DialFunc = net.Dial
	}

	return &Client{
		server:   config.Server,
		port:     config.Port,
		verbose:  config.Verbose,
		dialFunc: config.DialFunc,
	}
}

func (c *Client) Resolve(name string, resourceType dns.ResourceType) (*dns.Packet, error) {
	log.Info("Resolving DNS records...")
	received, err := c.question(&dns.Packet{
		Id:     uint16(rand.Int() % math.MaxUint16),
		QR:     dns.QRQuery,
		Opcode: dns.OpcodeQuery,
		RD:     true,
		Questions: []*dns.Question{
			{
				Qname:  name,
				Qtype:  resourceType,
				Qclass: dns.ClassIN,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("resolve name=%v resourceType=%v: %w", name, resourceType, err)
	}

	return received, nil
}

func (c *Client) question(sendPacket *dns.Packet) (*dns.Packet, error) {
	// connect to the DNS server
	var err error
	conn, err := c.dialFunc("udp", fmt.Sprintf("%s:%d", c.server, c.port))
	if err != nil {
		log.Errorf("dial server=%s: %v", c.server, err)
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// send a packet to the DNS server
	sendBuf, err := sendPacket.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode send packet: %w", err)
	}

	if c.verbose {
		fmt.Println("[SEND PACKET]")
		util.PrintHex(sendBuf)
	}
	_, err = conn.Write(sendBuf)
	if err != nil {
		return nil, fmt.Errorf("write send packet: %w", err)
	}

	// receive a packet from the DNS server
	recvBuf := make([]byte, 1024)
	recvLen, err := conn.Read(recvBuf)
	if err != nil {
		return nil, fmt.Errorf("read receive packet: %w", err)
	}

	if c.verbose {
		fmt.Println("[RECV PACKET]")
		util.PrintHex(recvBuf[:recvLen])
	}

	recvPacket, err := dns.DecodePacket(recvBuf)
	if err != nil {
		return nil, fmt.Errorf("decode receive packet: %w", err)
	}

	return recvPacket, nil
}
