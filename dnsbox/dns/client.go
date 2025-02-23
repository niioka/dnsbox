package dns

import (
	"fmt"
	"math"
	"math/rand/v2"
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

func (c *Client) Query(domain string) (*Packet, error) {
	var err error
	conn, err := net.Dial("udp", fmt.Sprintf("%s:53", c.server))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sendPacket := &Packet{
		Id:                 uint16(rand.Int() % math.MaxUint16),
		Qr:                 QRQuery,
		IsRecursionDesired: true,
		QuestionCount:      1,
		Questions: []*Question{
			{
				Qname:  domain,
				Qtype:  1,
				Qclass: 1,
			},
		},
	}
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
	recvPacket, err := DecodePacket(recvBuf)
	if err != nil {
		return nil, err
	}

	return recvPacket, nil
}
