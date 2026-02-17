package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"time"

	"pykeymouse/internal/config"
	"pykeymouse/internal/input"
	"pykeymouse/internal/proto"
)

func main() {
	var configPath string
	var mode string
	var duration time.Duration
	var rate int
	var count int

	flag.StringVar(&configPath, "config", "configs/client.json", "client config path")
	flag.StringVar(&mode, "mode", "load", "load|replay|invalid-password|latency|reconnect")
	flag.DurationVar(&duration, "duration", 10*time.Second, "duration for load test")
	flag.IntVar(&rate, "rate", 500, "events per second for load")
	flag.IntVar(&count, "count", 50, "count for latency/reconnect tests")
	flag.Parse()

	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	switch mode {
	case "invalid-password":
		if err := runInvalidPassword(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "replay":
		if err := runReplay(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "latency":
		if err := runLatency(cfg, count); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "reconnect":
		if err := runReconnect(cfg, count); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		if err := runLoad(cfg, duration, rate); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func runInvalidPassword(cfg config.ClientConfig) error {
	bad := flipHash(cfg.Auth.PasswordHash)
	_, _, _, _, err := dialAndHandshake(cfg, bad)
	if err == nil {
		return errors.New("expected auth failure but succeeded")
	}
	fmt.Println("auth failed as expected")
	return nil
}

func runReplay(cfg config.ClientConfig) error {
	conn, key, _, _, err := dialAndHandshake(cfg, "")
	if err != nil {
		return err
	}
	defer conn.Close()

	counter := uint64(1)
	msg := proto.Message{
		Type:      proto.TypeHeartbeat,
		Flags:     0,
		Counter:   counter,
		Timestamp: time.Now().UnixNano(),
	}
	if err := writeMessage(conn, msg, key); err != nil {
		return err
	}
	if err := writeMessage(conn, msg, key); err != nil {
		fmt.Println("replay rejected on duplicate send")
		return nil
	}

	counter++
	msg.Counter = counter
	msg.Timestamp = time.Now().UnixNano()
	err = writeMessage(conn, msg, key)
	if err == nil {
		return errors.New("replay was not detected")
	}
	fmt.Println("replay detected:", err)
	return nil
}

func runLatency(cfg config.ClientConfig, count int) error {
	conn, key, _, _, err := dialAndHandshake(cfg, "")
	if err != nil {
		return err
	}
	defer conn.Close()

	var total time.Duration
	for i := 0; i < count; i++ {
		counter := uint64(i + 1)
		sent := time.Now()
		msg := proto.Message{
			Type:      proto.TypeHeartbeat,
			Flags:     proto.HeartbeatFlagPing,
			Counter:   counter,
			Timestamp: sent.UnixNano(),
		}
		if err := writeMessage(conn, msg, key); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp, err := readMessage(conn, key)
		if err != nil {
			return err
		}
		if resp.Type != proto.TypeHeartbeat || resp.Flags&proto.HeartbeatFlagPong == 0 {
			return errors.New("unexpected response")
		}
		rtt := time.Since(sent)
		total += rtt
		fmt.Printf("pong %d: %v\n", i+1, rtt)
	}
	if count > 0 {
		fmt.Printf("avg: %v\n", total/time.Duration(count))
	}
	return nil
}

func runReconnect(cfg config.ClientConfig, count int) error {
	for i := 0; i < count; i++ {
		conn, key, _, _, err := dialAndHandshake(cfg, "")
		if err != nil {
			return err
		}
		msg := proto.Message{
			Type:      proto.TypeHeartbeat,
			Flags:     0,
			Counter:   1,
			Timestamp: time.Now().UnixNano(),
		}
		_ = writeMessage(conn, msg, key)
		_ = conn.Close()
		fmt.Printf("reconnect %d/%d ok\n", i+1, count)
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

func runLoad(cfg config.ClientConfig, duration time.Duration, rate int) error {
	conn, key, flags, _, err := dialAndHandshake(cfg, "")
	if err != nil {
		return err
	}
	defer conn.Close()

	if rate <= 0 {
		rate = 500
	}
	interval := time.Second / time.Duration(rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	end := time.Now().Add(duration)
	var counter uint64
	for time.Now().Before(end) {
		<-ticker.C
		counter++
		if flags&proto.AuthFlagMouse != 0 {
			dx := int32(rnd.Intn(7) - 3)
			dy := int32(rnd.Intn(7) - 3)
			msg := proto.Message{
				Type:      proto.TypeMouseMove,
				Flags:     0,
				Value:     proto.PackMouseDelta(dx, dy),
				Counter:   counter,
				Timestamp: time.Now().UnixNano(),
			}
			if err := writeMessage(conn, msg, key); err != nil {
				return err
			}
			continue
		}
		if flags&proto.AuthFlagKeyboard != 0 {
			value := int32(1)
			if counter%2 == 0 {
				value = 0
			}
			msg := proto.Message{
				Type:      proto.TypeKey,
				Flags:     0,
				Code:      0x1E,
				Value:     value,
				Counter:   counter,
				Timestamp: time.Now().UnixNano(),
			}
			if err := writeMessage(conn, msg, key); err != nil {
				return err
			}
		}
	}
	fmt.Println("load test complete")
	return nil
}

func dialAndHandshake(cfg config.ClientConfig, overrideHash string) (net.Conn, []byte, uint16, time.Time, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, nil, 0, time.Time{}, err
	}
	var d net.Dialer
	d.Timeout = 5 * time.Second
	d.KeepAlive = 30 * time.Second
	rawConn, err := d.Dial("tcp", cfg.ServerAddr)
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
	if err := verifyPin(tlsConn, cfg.TLS.ServerCertPinSHA256); err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}

	hello, err := proto.ReadServerHello(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}
	flags := clientFlags(cfg) & hello.Flags
	if flags == 0 {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, errors.New("no input types permitted")
	}

	hash := cfg.Auth.PasswordHash
	if overrideHash != "" {
		hash = overrideHash
	}
	auth := proto.ClientAuth{Flags: flags, HMAC: hmacSha256([]byte(hash), hello.Nonce[:])}
	if err := proto.WriteClientAuth(tlsConn, auth); err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}

	ok, err := proto.ReadServerAuthOK(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, 0, time.Time{}, err
	}
	sessionKey := make([]byte, len(ok.SessionKey))
	copy(sessionKey, ok.SessionKey[:])
	expiresAt := time.Unix(int64(ok.ExpiresAt), 0)
	return tlsConn, sessionKey, ok.Flags, expiresAt, nil
}

func buildTLSConfig(cfg config.ClientConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if cfg.TLS.ServerName != "" {
		tlsCfg.ServerName = cfg.TLS.ServerName
	}
	if cfg.TLS.CACertPath != "" {
		pemData, err := os.ReadFile(cfg.TLS.CACertPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, errors.New("failed to parse CA cert")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func verifyPin(conn *tls.Conn, pinHex string) error {
	if pinHex == "" {
		return nil
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("no server certificate")
	}
	pinBytes, err := hex.DecodeString(pinHex)
	if err != nil || len(pinBytes) != 32 {
		return errors.New("invalid pin format")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if !hmac.Equal(sum[:], pinBytes) {
		return errors.New("server certificate pin mismatch")
	}
	return nil
}

func clientFlags(cfg config.ClientConfig) uint16 {
	var flags uint16
	if cfg.Input.EnableKeyboard != nil && *cfg.Input.EnableKeyboard {
		flags |= proto.AuthFlagKeyboard
	}
	if cfg.Input.EnableMouse != nil && *cfg.Input.EnableMouse {
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

func readMessage(conn net.Conn, key []byte) (proto.Message, error) {
	buf := make([]byte, proto.WireSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return proto.Message{}, err
	}
	return proto.Decode(buf, key)
}

func hmacSha256(key []byte, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func flipHash(hash string) string {
	if len(hash) == 0 {
		return hash
	}
	b := []byte(hash)
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	return string(b)
}

var _ = input.Event{} // force module dependency for tests
