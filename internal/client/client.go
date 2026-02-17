package client

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"os"
	"time"

	"pykeymouse/internal/config"
	"pykeymouse/internal/input"
	"pykeymouse/internal/proto"
)

type Client struct {
	cfg    config.ClientConfig
	logger *log.Logger
}

func New(cfg config.ClientConfig, logger *log.Logger) *Client {
	if logger == nil {
		logger = log.New(os.Stdout, "client: ", log.LstdFlags)
	}
	return &Client{cfg: cfg, logger: logger}
}

func (c *Client) Run(ctx context.Context, events <-chan input.Event) error {
	bo := newBackoff(c.cfg.ReconnectInitial(), c.cfg.ReconnectMax())
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, session, flags, expiresAt, err := c.connectAndAuth(ctx)
		if err != nil {
			c.logger.Printf("connect/auth failed: %v", err)
			sleepWithContext(ctx, bo.Next())
			continue
		}
		bo.Reset()
		err = c.sessionLoop(ctx, conn, session, flags, expiresAt, events)
		_ = conn.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.logger.Printf("session ended: %v", err)
		sleepWithContext(ctx, bo.Next())
	}
}

func (c *Client) connectAndAuth(ctx context.Context) (net.Conn, []byte, uint16, time.Time, error) {
	tlsCfg, err := c.tlsConfig()
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	var d net.Dialer
	d.Timeout = 5 * time.Second
	d.KeepAlive = 30 * time.Second
	rawConn, err := d.DialContext(ctx, "tcp", c.cfg.ServerAddr)
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, nil, 0, time.Time{}, err
	}
	if err := c.verifyPin(tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}

	hello, err := proto.ReadServerHello(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}
	flags := c.clientFlags() & hello.Flags
	if flags == 0 {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, errors.New("no input types permitted")
	}

	expected := hmacSha256([]byte(c.cfg.Auth.PasswordHash), hello.Nonce[:])
	auth := proto.ClientAuth{Flags: flags, HMAC: expected}
	if err := proto.WriteClientAuth(tlsConn, auth); err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}
	ok, err := proto.ReadServerAuthOK(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}
	if ok.Flags == 0 {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, errors.New("server returned no flags")
	}

	sessionKey := make([]byte, len(ok.SessionKey))
	copy(sessionKey, ok.SessionKey[:])
	expiresAt := time.Unix(int64(ok.ExpiresAt), 0)
	return tlsConn, sessionKey, ok.Flags, expiresAt, nil
}

func (c *Client) sessionLoop(ctx context.Context, conn net.Conn, key []byte, flags uint16, expiresAt time.Time, events <-chan input.Event) error {
	var counter uint64
	heartbeat := time.NewTicker(c.cfg.HeartbeatInterval())
	defer heartbeat.Stop()

	for {
		if !expiresAt.IsZero() && time.Now().After(expiresAt) {
			return errors.New("session expired")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				return errors.New("event channel closed")
			}
			if ev.Type == input.EventKey && (flags&proto.AuthFlagKeyboard == 0) {
				continue
			}
			if ev.Type != input.EventKey && (flags&proto.AuthFlagMouse == 0) {
				continue
			}
			counter++
			msg := proto.Message{
				Type:      ev.Type,
				Flags:     ev.Flags,
				Code:      ev.Code,
				Value:     ev.Value,
				Counter:   counter,
				Timestamp: time.Now().UnixNano(),
			}
			if err := writeMessage(conn, msg, key); err != nil {
				return err
			}
		case <-heartbeat.C:
			counter++
			msg := proto.Message{
				Type:      proto.TypeHeartbeat,
				Flags:     0,
				Counter:   counter,
				Timestamp: time.Now().UnixNano(),
			}
			if err := writeMessage(conn, msg, key); err != nil {
				return err
			}
		}
	}
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if c.cfg.TLS.ServerName != "" {
		cfg.ServerName = c.cfg.TLS.ServerName
	}
	if c.cfg.TLS.CACertPath != "" {
		pemData, err := os.ReadFile(c.cfg.TLS.CACertPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, errors.New("failed to parse CA cert")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (c *Client) verifyPin(conn *tls.Conn) error {
	if c.cfg.TLS.ServerCertPinSHA256 == "" {
		return nil
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("no server certificate")
	}
	pinBytes, err := hex.DecodeString(c.cfg.TLS.ServerCertPinSHA256)
	if err != nil || len(pinBytes) != 32 {
		return errors.New("invalid pin format")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if !hmac.Equal(sum[:], pinBytes) {
		return errors.New("server certificate pin mismatch")
	}
	return nil
}

func (c *Client) clientFlags() uint16 {
	var flags uint16
	if c.cfg.Input.EnableKeyboard != nil && *c.cfg.Input.EnableKeyboard {
		flags |= proto.AuthFlagKeyboard
	}
	if c.cfg.Input.EnableMouse != nil && *c.cfg.Input.EnableMouse {
		flags |= proto.AuthFlagMouse
	}
	return flags
}

func writeMessage(conn net.Conn, msg proto.Message, key []byte) error {
	out, _ := proto.Encode(msg, key)
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write(out[:])
	return err
}

func hmacSha256(key []byte, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type backoff struct {
	initial time.Duration
	max     time.Duration
	current time.Duration
}

func newBackoff(initial, max time.Duration) *backoff {
	return &backoff{initial: initial, max: max, current: initial}
}

func (b *backoff) Next() time.Duration {
	if b.current == 0 {
		b.current = b.initial
	}
	d := b.current
	next := b.current * 2
	if next > b.max {
		next = b.max
	}
	b.current = next
	return d
}

func (b *backoff) Reset() {
	b.current = b.initial
}

func sleepWithContext(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
