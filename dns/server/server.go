package server

import (
	"errors"
	"fmt"
	"github.com/niioka/dnsbox/dns"
	"github.com/niioka/dnsbox/dns/client"
	log "github.com/sirupsen/logrus"
	"net"
)

type Server struct {
	ip     net.IP
	port   int
	conn   net.Conn
	client *client.Client
}

type ServerConfig struct {
	Ip     string
	Port   int
	Client *client.Client
}

func NewServer(config ServerConfig) *Server {
	if config.Ip == "" {
		config.Ip = "0.0.0.0"
	}
	if config.Port == 0 {
		config.Port = 53
	}
	if config.Client == nil {
		config.Client = client.New(client.Config{
			Server: "8.8.8.8",
		})
	}
	return &Server{
		ip:     net.ParseIP(config.Ip),
		port:   config.Port,
		client: config.Client,
	}
}

func (s *Server) Start() error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   s.ip,
		Port: s.port,
	})
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	s.conn = conn
	defer func() { _ = conn.Close() }()
	log.Printf("Started DNS Server on UDP port 53.")

	buf := make([]byte, 1024)
	for {
		rxPacket, err := s.readPacket(conn, buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Errorf("Failed to read packet: %v+", err)
			continue
		}

		go s.handlePacket(rxPacket)
	}
}

func (s *Server) Stop() error {
	return s.conn.Close()
}

func (s *Server) readPacket(conn *net.UDPConn, buf []byte) (*dns.Packet, error) {
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from UDP: %w", err)
	}

	input := buf[0:n]
	return dns.DecodePacket(input)
}

func (s *Server) handlePacket(rxPacket *dns.Packet) {
	question := rxPacket.Questions[0]
	records, err := s.client.Resolve(question.Qname, question.Qtype)
	if err != nil {
		log.Errorf("Failed to resolve records: %v", err)
		return
	}

	log.Infof("Resolved %+v records.", records)
}
