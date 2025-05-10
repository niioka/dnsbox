package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrInvalidPosition = errors.New("invalid position")

type Scanner struct {
	buf  []byte
	pos  int
	stop int
}

func NewScanner(buf []byte) *Scanner {
	return &Scanner{
		buf:  buf,
		stop: len(buf),
	}
}

func (s *Scanner) Length() int {
	return s.stop
}

func (s *Scanner) ReadByte() (byte, error) {
	if !s.HasSpace(1) {
		return 0, fmt.Errorf("ReadByte pos=%d len=%d: too short", s.pos, s.stop)
	}
	n := s.buf[s.pos]
	s.pos += 1
	return n, nil
}

func (s *Scanner) ReadBytes(n int) ([]byte, error) {
	buf, err := s.PeekBytesFrom(s.pos, n)
	if err != nil {
		return nil, err
	}
	s.pos += n
	return buf, nil
}

func (s *Scanner) PeekBytesFrom(pos int, n int) ([]byte, error) {
	if pos+n > s.stop {
		return nil, fmt.Errorf("PeekBytesFrom buffer overrun: currentPos + n > bufferSize (currentPos=%d n=%d bufferSize=%d)", pos, n, s.stop)
	}
	b := s.buf[pos : pos+n]
	return b, nil
}

func (s *Scanner) ReadUint16() (uint16, error) {
	if !s.HasSpace(2) {
		return 0, fmt.Errorf("ReadUint16 pos=%d len=%d: too short", s.pos, s.stop)
	}
	n := binary.BigEndian.Uint16(s.buf[s.pos:])
	s.pos += 2
	return n, nil
}

func (s *Scanner) ReadUint32() (uint32, error) {
	if !s.HasSpace(4) {
		return 0, fmt.Errorf("too short: pos=%d", s.pos)
	}
	n := binary.BigEndian.Uint32(s.buf[s.pos:])
	s.pos += 4
	return n, nil
}

func (s *Scanner) HasSpace(length int) bool {
	return s.pos+length <= s.stop
}

func (s *Scanner) HasSpaceFrom(pos, length int) bool {
	return pos+length <= s.stop
}

func (s *Scanner) Position() int {
	return s.pos
}

func (s *Scanner) IsValidPosition(pos int) bool {
	return pos >= 0 && pos < len(s.buf)
}

func (s *Scanner) Peek() (byte, error) {
	return s.PeekAt(s.pos)
}

func (s *Scanner) PeekAt(pos int) (byte, error) {
	if s.IsValidPosition(s.pos) {
		return s.buf[pos], nil
	}
	return 0, ErrInvalidPosition
}

func (s *Scanner) Skip(n int) {
	s.pos += n
}
