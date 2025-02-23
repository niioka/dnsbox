package dns

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"math"
	"math/rand"
	"net"
)

type Client struct {
	server string
}

func NewClient(server string) *Client {
	return &Client{
		server: server,
	}
}

func (c *Client) ResolveA(domain string) ([]*ResourceRecord, error) {
	recvPacket, err := c.question(&Packet{
		Id:                 uint16(rand.Int() % math.MaxUint16),
		Qr:                 QRQuery,
		IsRecursionDesired: true,
		QuestionCount:      1,
		Questions: []*Question{
			{
				Qname:  domain,
				Qtype:  TypeA,
				Qclass: 1,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	fmt.Printf("recvPacket: %+v", spew.Sdump(recvPacket))

	return recvPacket.Answers, nil
}

func (c *Client) ResolveTXT(domain string) ([]*ResourceRecord, error) {
	recvPacket, err := c.question(&Packet{
		Id:                 uint16(rand.Int() % math.MaxUint16),
		Qr:                 QRQuery,
		IsRecursionDesired: true,
		QuestionCount:      1,
		Questions: []*Question{
			{
				Qname:  domain,
				Qtype:  TypeTXT,
				Qclass: 1,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	fmt.Printf("recvPacket: %+v", spew.Sdump(recvPacket))

	return recvPacket.Answers, nil
}

func (c *Client) question(sendPacket *Packet) (*Packet, error) {
	var err error
	conn, err := net.Dial("udp", fmt.Sprintf("%s:53", c.server))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sendBuf, err := EncodePacket(sendPacket)
	fmt.Printf("sendPacket: %+v\n", sendPacket)
	fmt.Printf("sendBuf: %+v\n", sendBuf)
	_, err = conn.Write(sendBuf)
	if err != nil {
		return nil, err
	}

	recvBuf := make([]byte, 1024)
	recvLen, err := conn.Read(recvBuf)
	if err != nil {
		return nil, err
	}

	fmt.Printf("recvLen: %d recvBuf: %v\n", recvLen, recvBuf[0:recvLen])
	var pd PacketDecoder
	recvPacket, err := pd.DecodePacket(recvBuf)
	if err != nil {
		return nil, err
	}

	return recvPacket, nil
}
