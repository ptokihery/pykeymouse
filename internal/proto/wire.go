package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

const (
	WireSize   = 56
	HeaderSize = 24
)

const (
	TypeKey         = 1
	TypeMouseMove   = 2
	TypeMouseButton = 3
	TypeWheel       = 4
	TypeHeartbeat   = 5
)

const (
	HeartbeatFlagPing = 1 << 0
	HeartbeatFlagPong = 1 << 1
)

type Message struct {
	Type      uint8
	Flags     uint8
	Code      uint16
	Value     int32
	Counter   uint64
	Timestamp int64
}

var (
	ErrInvalidSize = errors.New("invalid message size")
	ErrInvalidHMAC = errors.New("invalid hmac")
)

func Encode(m Message, key []byte) ([WireSize]byte, error) {
	var out [WireSize]byte
	out[0] = m.Type
	out[1] = m.Flags
	binary.BigEndian.PutUint16(out[2:], m.Code)
	binary.BigEndian.PutUint32(out[4:], uint32(m.Value))
	binary.BigEndian.PutUint64(out[8:], m.Counter)
	binary.BigEndian.PutUint64(out[16:], uint64(m.Timestamp))
	mac := computeHMAC(key, out[:HeaderSize])
	copy(out[HeaderSize:], mac[:])
	return out, nil
}

func Decode(buf []byte, key []byte) (Message, error) {
	if len(buf) != WireSize {
		return Message{}, ErrInvalidSize
	}
	expected := computeHMAC(key, buf[:HeaderSize])
	if !hmac.Equal(buf[HeaderSize:], expected[:]) {
		return Message{}, ErrInvalidHMAC
	}
	m := Message{
		Type:      buf[0],
		Flags:     buf[1],
		Code:      binary.BigEndian.Uint16(buf[2:]),
		Value:     int32(binary.BigEndian.Uint32(buf[4:])),
		Counter:   binary.BigEndian.Uint64(buf[8:]),
		Timestamp: int64(binary.BigEndian.Uint64(buf[16:])),
	}
	return m, nil
}

func computeHMAC(key []byte, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func PackMouseDelta(dx int32, dy int32) int32 {
	if dx > math.MaxInt16 {
		dx = math.MaxInt16
	} else if dx < math.MinInt16 {
		dx = math.MinInt16
	}
	if dy > math.MaxInt16 {
		dy = math.MaxInt16
	} else if dy < math.MinInt16 {
		dy = math.MinInt16
	}
	ux := uint32(uint16(int16(dx)))
	uy := uint32(uint16(int16(dy)))
	return int32((ux << 16) | uy)
}

func UnpackMouseDelta(v int32) (int16, int16) {
	ux := uint16(uint32(v) >> 16)
	uy := uint16(uint32(v) & 0xFFFF)
	return int16(ux), int16(uy)
}
