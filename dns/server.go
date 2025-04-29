package dns

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
)

type Server struct {
	ip     net.IP
	port   int
	client *Client
}

type ServerConfig struct {
	Ip     string
	Port   int
	Client *Client
}

func NewServer(config ServerConfig) *Server {
	if config.Ip == "" {
		config.Ip = "0.0.0.0"
	}
	if config.Port == 0 {
		config.Port = 53
	}
	if config.Client == nil {
		config.Client = NewClient("8.8.8.8")
	}
	return &Server{
		ip:     net.ParseIP(config.Ip),
		port:   config.Port,
		client: config.Client,
	}
}

func (s *Server) Start() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   s.ip,
		Port: s.port,
	})
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	log.Printf("Started DNS Server on UDP port 53.")

	buf := make([]byte, 1024)
	for {
		rxPacket, err := s.readPacket(conn, buf)
		if err != nil {
			log.Errorf("Failed to read packet: %v", err)
			continue
		}

		question := rxPacket.Questions[0]
		q := &Question{
			Qname:  question.Qname,
			Qtype:  question.Qtype,
			Qclass: 1,
		}
		records, err := s.client.Resolve(q)
		if err != nil {
			log.Errorf("Failed to resolve records: %v", err)
			continue
		}

		log.Infof("Resolved %+v records.", records)
	}
}

func (s *Server) readPacket(conn *net.UDPConn, buf []byte) (*Packet, error) {
	var pd PacketDecoder
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from UDP: %v", err)
	}
	input := buf[0:n]
	return pd.DecodePacket(input)
}
