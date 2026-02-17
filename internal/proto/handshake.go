package proto

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	HandshakeMagic   = "PKM1"
	HandshakeVersion = 1
)

const (
	AuthFlagKeyboard = 1 << 0
	AuthFlagMouse    = 1 << 1
)

const (
	serverHelloSize = 4 + 2 + 2 + 32 + 4 + 4 + 4
	clientAuthSize  = 4 + 2 + 2 + 32
	serverOKSize    = 4 + 2 + 2 + 32 + 16 + 8
)

var (
	ErrBadMagic   = errors.New("bad handshake magic")
	ErrBadVersion = errors.New("bad handshake version")
)

type ServerHello struct {
	Flags                 uint16
	Nonce                 [32]byte
	SessionTimeoutSeconds uint32
	InactivitySeconds     uint32
	SkewSeconds           uint32
}

type ClientAuth struct {
	Flags uint16
	HMAC  [32]byte
}

type ServerAuthOK struct {
	Flags      uint16
	SessionKey [32]byte
	SessionID  [16]byte
	ExpiresAt  uint64
}

func WriteServerHello(w io.Writer, h ServerHello) error {
	var buf [serverHelloSize]byte
	copy(buf[0:4], []byte(HandshakeMagic))
	binary.BigEndian.PutUint16(buf[4:], HandshakeVersion)
	binary.BigEndian.PutUint16(buf[6:], h.Flags)
	copy(buf[8:], h.Nonce[:])
	binary.BigEndian.PutUint32(buf[40:], h.SessionTimeoutSeconds)
	binary.BigEndian.PutUint32(buf[44:], h.InactivitySeconds)
	binary.BigEndian.PutUint32(buf[48:], h.SkewSeconds)
	_, err := w.Write(buf[:])
	return err
}

func ReadServerHello(r io.Reader) (ServerHello, error) {
	var buf [serverHelloSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return ServerHello{}, err
	}
	if string(buf[0:4]) != HandshakeMagic {
		return ServerHello{}, ErrBadMagic
	}
	if binary.BigEndian.Uint16(buf[4:]) != HandshakeVersion {
		return ServerHello{}, ErrBadVersion
	}
	h := ServerHello{
		Flags:                 binary.BigEndian.Uint16(buf[6:]),
		SessionTimeoutSeconds: binary.BigEndian.Uint32(buf[40:]),
		InactivitySeconds:     binary.BigEndian.Uint32(buf[44:]),
		SkewSeconds:           binary.BigEndian.Uint32(buf[48:]),
	}
	copy(h.Nonce[:], buf[8:40])
	return h, nil
}

func WriteClientAuth(w io.Writer, c ClientAuth) error {
	var buf [clientAuthSize]byte
	copy(buf[0:4], []byte(HandshakeMagic))
	binary.BigEndian.PutUint16(buf[4:], HandshakeVersion)
	binary.BigEndian.PutUint16(buf[6:], c.Flags)
	copy(buf[8:], c.HMAC[:])
	_, err := w.Write(buf[:])
	return err
}

func ReadClientAuth(r io.Reader) (ClientAuth, error) {
	var buf [clientAuthSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return ClientAuth{}, err
	}
	if string(buf[0:4]) != HandshakeMagic {
		return ClientAuth{}, ErrBadMagic
	}
	if binary.BigEndian.Uint16(buf[4:]) != HandshakeVersion {
		return ClientAuth{}, ErrBadVersion
	}
	var c ClientAuth
	c.Flags = binary.BigEndian.Uint16(buf[6:])
	copy(c.HMAC[:], buf[8:])
	return c, nil
}

func WriteServerAuthOK(w io.Writer, s ServerAuthOK) error {
	var buf [serverOKSize]byte
	copy(buf[0:4], []byte(HandshakeMagic))
	binary.BigEndian.PutUint16(buf[4:], HandshakeVersion)
	binary.BigEndian.PutUint16(buf[6:], s.Flags)
	copy(buf[8:], s.SessionKey[:])
	copy(buf[40:], s.SessionID[:])
	binary.BigEndian.PutUint64(buf[56:], s.ExpiresAt)
	_, err := w.Write(buf[:])
	return err
}

func ReadServerAuthOK(r io.Reader) (ServerAuthOK, error) {
	var buf [serverOKSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return ServerAuthOK{}, err
	}
	if string(buf[0:4]) != HandshakeMagic {
		return ServerAuthOK{}, ErrBadMagic
	}
	if binary.BigEndian.Uint16(buf[4:]) != HandshakeVersion {
		return ServerAuthOK{}, ErrBadVersion
	}
	var s ServerAuthOK
	s.Flags = binary.BigEndian.Uint16(buf[6:])
	copy(s.SessionKey[:], buf[8:40])
	copy(s.SessionID[:], buf[40:56])
	s.ExpiresAt = binary.BigEndian.Uint64(buf[56:])
	return s, nil
}
