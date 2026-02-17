package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"pykeymouse/internal/config"
	"pykeymouse/internal/input"
	"pykeymouse/internal/keymap"
	"pykeymouse/internal/proto"
)

type Server struct {
	cfg        config.ServerConfig
	tlsConfig  *tls.Config
	allowedNet *net.IPNet
	active     atomic.Bool
	logger     *log.Logger
}

func New(cfg config.ServerConfig, logger *log.Logger) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertPath, cfg.TLS.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load tls keypair: %w", err)
	}
	allowedNet, err := parseAllowedIP(cfg.AllowedIP)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(os.Stdout, "server: ", log.LstdFlags)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	return &Server{cfg: cfg, tlsConfig: tlsCfg, allowedNet: allowedNet, logger: logger}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Printf("accept error: %v", err)
			continue
		}
		if !s.active.CompareAndSwap(false, true) {
			_ = conn.Close()
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.active.Store(false)
	defer conn.Close()

	if !s.isAllowed(conn.RemoteAddr()) {
		s.logger.Printf("connection refused from %v", conn.RemoteAddr())
		return
	}

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	tlsConn := tls.Server(conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.logger.Printf("tls handshake failed: %v", err)
		return
	}
	defer tlsConn.Close()

	key, flags, expiresAt, err := s.handshake(tlsConn)
	if err != nil {
		s.logger.Printf("auth failed: %v", err)
		return
	}

	enableKeyboard := s.flagEnabled(proto.AuthFlagKeyboard) && (flags&proto.AuthFlagKeyboard != 0)
	enableMouse := s.flagEnabled(proto.AuthFlagMouse) && (flags&proto.AuthFlagMouse != 0)

	dev, err := input.OpenUInput(enableKeyboard, enableMouse, keymap.SupportedKeyCodes())
	if err != nil {
		s.logger.Printf("uinput setup failed: %v", err)
		return
	}
	defer dev.Close()

	if err := s.sessionLoop(tlsConn, dev, key, expiresAt, enableKeyboard, enableMouse); err != nil {
		s.logger.Printf("session ended: %v", err)
	}
}

func (s *Server) handshake(conn net.Conn) ([]byte, uint16, time.Time, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, 0, time.Time{}, err
	}
	serverFlags := s.serverFlags()
	hello := proto.ServerHello{
		Flags:                 serverFlags,
		Nonce:                 nonce,
		SessionTimeoutSeconds: uint32(s.cfg.Session.TimeoutSeconds),
		InactivitySeconds:     uint32(s.cfg.Session.InactivitySeconds),
		SkewSeconds:           uint32(s.cfg.Session.SkewSeconds),
	}
	if err := proto.WriteServerHello(conn, hello); err != nil {
		return nil, 0, time.Time{}, err
	}
	auth, err := proto.ReadClientAuth(conn)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	expected := hmacSha256([]byte(s.cfg.Auth.PasswordHash), nonce[:])
	if !hmac.Equal(auth.HMAC[:], expected[:]) {
		return nil, 0, time.Time{}, errors.New("invalid auth hmac")
	}
	flags := auth.Flags & serverFlags
	if flags == 0 {
		return nil, 0, time.Time{}, errors.New("no input allowed")
	}

	var sessionKey [32]byte
	var sessionID [16]byte
	if _, err := rand.Read(sessionKey[:]); err != nil {
		return nil, 0, time.Time{}, err
	}
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, 0, time.Time{}, err
	}
	expiresAt := time.Now().Add(time.Duration(s.cfg.Session.TimeoutSeconds) * time.Second)
	ok := proto.ServerAuthOK{
		Flags:      flags,
		SessionKey: sessionKey,
		SessionID:  sessionID,
		ExpiresAt:  uint64(expiresAt.Unix()),
	}
	if err := proto.WriteServerAuthOK(conn, ok); err != nil {
		return nil, 0, time.Time{}, err
	}
	return sessionKey[:], flags, expiresAt, nil
}

func (s *Server) sessionLoop(conn net.Conn, dev *input.UInputDevice, key []byte, expiresAt time.Time, enableKeyboard, enableMouse bool) error {
	var counter uint64
	lastActivity := time.Now()
	inactivity := time.Duration(s.cfg.Session.InactivitySeconds) * time.Second
	skew := time.Duration(s.cfg.Session.SkewSeconds) * time.Second
	maxPerSec := s.cfg.Security.MaxEventsPerSecond
	windowStart := time.Now()
	windowCount := 0

	buf := make([]byte, proto.WireSize)
	for {
		now := time.Now()
		if now.After(expiresAt) {
			return errors.New("session expired")
		}
		if now.Sub(lastActivity) > inactivity {
			return errors.New("session inactive")
		}
		_ = conn.SetReadDeadline(time.Now().Add(inactivity))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		msg, err := proto.Decode(buf, key)
		if err != nil {
			return err
		}
		if msg.Counter <= counter {
			return errors.New("replay detected")
		}
		counter = msg.Counter

		now = time.Now()
		if skew > 0 {
			delta := now.UnixNano() - msg.Timestamp
			if delta < 0 {
				delta = -delta
			}
			if time.Duration(delta) > skew {
				return errors.New("timestamp outside window")
			}
		}
		lastActivity = now

		if maxPerSec > 0 {
			if now.Sub(windowStart) >= time.Second {
				windowStart = now
				windowCount = 0
			}
			windowCount++
			if windowCount > maxPerSec {
				return errors.New("rate limit")
			}
		}

		switch msg.Type {
		case proto.TypeKey:
			if !enableKeyboard {
				continue
			}
			value := msg.Value
			if value < 0 {
				value = 0
			} else if value > 2 {
				value = 1
			}
			if err := dev.EmitKey(msg.Code, value); err != nil {
				return err
			}
			if err := dev.Sync(); err != nil {
				return err
			}
		case proto.TypeMouseMove:
			if !enableMouse {
				continue
			}
			dx, dy := proto.UnpackMouseDelta(msg.Value)
			if dx == 0 && dy == 0 {
				continue
			}
			if dx != 0 {
				if err := dev.EmitRel(input.REL_X, int32(dx)); err != nil {
					return err
				}
			}
			if dy != 0 {
				if err := dev.EmitRel(input.REL_Y, int32(dy)); err != nil {
					return err
				}
			}
			if err := dev.Sync(); err != nil {
				return err
			}
		case proto.TypeMouseButton:
			if !enableMouse {
				continue
			}
			value := msg.Value
			if value != 0 {
				value = 1
			}
			if err := dev.EmitKey(msg.Code, value); err != nil {
				return err
			}
			if err := dev.Sync(); err != nil {
				return err
			}
		case proto.TypeWheel:
			if !enableMouse {
				continue
			}
			value := msg.Value
			if value%120 == 0 {
				value = value / 120
			}
			if err := dev.EmitRel(input.REL_WHEEL, value); err != nil {
				return err
			}
			if err := dev.Sync(); err != nil {
				return err
			}
		case proto.TypeHeartbeat:
			if s.cfg.Test.EnableEcho && (msg.Flags&proto.HeartbeatFlagPing != 0) {
				pong := proto.Message{
					Type:      proto.TypeHeartbeat,
					Flags:     proto.HeartbeatFlagPong,
					Counter:   msg.Counter,
					Timestamp: time.Now().UnixNano(),
				}
				out, _ := proto.Encode(pong, key)
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write(out[:])
			}
		default:
			continue
		}
	}
}

func (s *Server) serverFlags() uint16 {
	var flags uint16
	if s.flagEnabled(proto.AuthFlagKeyboard) {
		flags |= proto.AuthFlagKeyboard
	}
	if s.flagEnabled(proto.AuthFlagMouse) {
		flags |= proto.AuthFlagMouse
	}
	return flags
}

func (s *Server) flagEnabled(flag uint16) bool {
	switch flag {
	case proto.AuthFlagKeyboard:
		return s.cfg.Input.EnableKeyboard != nil && *s.cfg.Input.EnableKeyboard
	case proto.AuthFlagMouse:
		return s.cfg.Input.EnableMouse != nil && *s.cfg.Input.EnableMouse
	default:
		return false
	}
}

func (s *Server) isAllowed(addr net.Addr) bool {
	if s.allowedNet == nil {
		return true
	}
	var ip net.IP
	if tcp, ok := addr.(*net.TCPAddr); ok {
		ip = tcp.IP
	} else {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil {
		return false
	}
	return s.allowedNet.Contains(ip)
}

func parseAllowedIP(value string) (*net.IPNet, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	if strings.Contains(value, "/") {
		_, netw, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed_ip: %w", err)
		}
		return netw, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, errors.New("invalid allowed_ip")
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	mask := net.CIDRMask(bits, bits)
	return &net.IPNet{IP: ip, Mask: mask}, nil
}

func hmacSha256(key []byte, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
