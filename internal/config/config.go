package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type TLSConfig struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

type ClientTLSConfig struct {
	CACertPath          string `json:"ca_cert_path"`
	ServerName          string `json:"server_name"`
	ServerCertPinSHA256 string `json:"server_cert_pin_sha256"`
}

type AuthConfig struct {
	PasswordHash string `json:"password_hash_bcrypt"`
}

type SessionConfig struct {
	TimeoutSeconds    int `json:"timeout_seconds"`
	InactivitySeconds int `json:"inactivity_seconds"`
	SkewSeconds       int `json:"skew_seconds"`
}

type InputConfig struct {
	EnableKeyboard *bool `json:"enable_keyboard"`
	EnableMouse    *bool `json:"enable_mouse"`
}

type SecurityConfig struct {
	MaxEventsPerSecond int `json:"max_events_per_sec"`
}

type TestConfig struct {
	EnableEcho bool `json:"enable_echo"`
}

type ServerConfig struct {
	ListenAddr string         `json:"listen_addr"`
	AllowedIP  string         `json:"allowed_ip"`
	TLS        TLSConfig      `json:"tls"`
	Auth       AuthConfig     `json:"auth"`
	Session    SessionConfig  `json:"session"`
	Input      InputConfig    `json:"input"`
	Security   SecurityConfig `json:"security"`
	Test       TestConfig     `json:"test"`
}

type ReconnectConfig struct {
	InitialDelayMs int `json:"initial_delay_ms"`
	MaxDelayMs     int `json:"max_delay_ms"`
}

type ClientConfig struct {
	ServerAddr               string          `json:"server_addr"`
	TLS                      ClientTLSConfig `json:"tls"`
	Auth                     AuthConfig      `json:"auth"`
	Input                    InputConfig     `json:"input"`
	HeartbeatIntervalSeconds int             `json:"heartbeat_interval_seconds"`
	MouseAggregateMs         int             `json:"mouse_aggregate_ms"`
	Reconnect                ReconnectConfig `json:"reconnect"`
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr: "0.0.0.0:8443",
		Session: SessionConfig{
			TimeoutSeconds:    600,
			InactivitySeconds: 600,
			SkewSeconds:       5,
		},
		Input: InputConfig{
			EnableKeyboard: boolPtr(true),
			EnableMouse:    boolPtr(true),
		},
		Security: SecurityConfig{
			MaxEventsPerSecond: 5000,
		},
		Test: TestConfig{EnableEcho: false},
	}
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		HeartbeatIntervalSeconds: 3,
		MouseAggregateMs:         1,
		Input: InputConfig{
			EnableKeyboard: boolPtr(true),
			EnableMouse:    boolPtr(true),
		},
		Reconnect: ReconnectConfig{
			InitialDelayMs: 250,
			MaxDelayMs:     5000,
		},
	}
}

func LoadServerConfig(path string) (ServerConfig, error) {
	var cfg ServerConfig
	if path == "" {
		return cfg, errors.New("config path required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	cfg.normalizeServer()
	if err := cfg.validateServer(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func LoadClientConfig(path string) (ClientConfig, error) {
	var cfg ClientConfig
	if path == "" {
		return cfg, errors.New("config path required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	cfg.normalizeClient()
	if err := cfg.validateClient(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *ServerConfig) normalizeServer() {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:8443"
	}
	if c.Session.TimeoutSeconds == 0 {
		c.Session.TimeoutSeconds = 600
	}
	if c.Session.InactivitySeconds == 0 {
		c.Session.InactivitySeconds = 600
	}
	if c.Session.SkewSeconds == 0 {
		c.Session.SkewSeconds = 5
	}
	if c.Input.EnableKeyboard == nil {
		c.Input.EnableKeyboard = boolPtr(true)
	}
	if c.Input.EnableMouse == nil {
		c.Input.EnableMouse = boolPtr(true)
	}
	if c.Security.MaxEventsPerSecond == 0 {
		c.Security.MaxEventsPerSecond = 5000
	}
}

func (c *ClientConfig) normalizeClient() {
	if c.HeartbeatIntervalSeconds == 0 {
		c.HeartbeatIntervalSeconds = 3
	}
	if c.MouseAggregateMs == 0 {
		c.MouseAggregateMs = 1
	}
	if c.Input.EnableKeyboard == nil {
		c.Input.EnableKeyboard = boolPtr(true)
	}
	if c.Input.EnableMouse == nil {
		c.Input.EnableMouse = boolPtr(true)
	}
	if c.Reconnect.InitialDelayMs == 0 {
		c.Reconnect.InitialDelayMs = 250
	}
	if c.Reconnect.MaxDelayMs == 0 {
		c.Reconnect.MaxDelayMs = 5000
	}
}

func (c ServerConfig) validateServer() error {
	if c.ListenAddr == "" {
		return errors.New("listen_addr required")
	}
	if c.TLS.CertPath == "" || c.TLS.KeyPath == "" {
		return errors.New("tls.cert_path and tls.key_path required")
	}
	if c.Auth.PasswordHash == "" {
		return errors.New("auth.password_hash_bcrypt required")
	}
	if _, err := bcrypt.Cost([]byte(c.Auth.PasswordHash)); err != nil {
		return fmt.Errorf("invalid bcrypt hash: %w", err)
	}
	if c.Session.TimeoutSeconds <= 0 || c.Session.InactivitySeconds <= 0 || c.Session.SkewSeconds <= 0 {
		return errors.New("session timeouts must be > 0")
	}
	return nil
}

func (c ClientConfig) validateClient() error {
	if c.ServerAddr == "" {
		return errors.New("server_addr required")
	}
	if c.Auth.PasswordHash == "" {
		return errors.New("auth.password_hash_bcrypt required")
	}
	if _, err := bcrypt.Cost([]byte(c.Auth.PasswordHash)); err != nil {
		return fmt.Errorf("invalid bcrypt hash: %w", err)
	}
	if c.HeartbeatIntervalSeconds <= 0 {
		return errors.New("heartbeat_interval_seconds must be > 0")
	}
	if c.MouseAggregateMs <= 0 {
		return errors.New("mouse_aggregate_ms must be > 0")
	}
	if c.Reconnect.InitialDelayMs <= 0 || c.Reconnect.MaxDelayMs <= 0 {
		return errors.New("reconnect delays must be > 0")
	}
	if c.TLS.ServerCertPinSHA256 != "" {
		b, err := hex.DecodeString(c.TLS.ServerCertPinSHA256)
		if err != nil || len(b) != 32 {
			return errors.New("tls.server_cert_pin_sha256 must be 64 hex chars")
		}
	}
	return nil
}

func (c ClientConfig) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSeconds) * time.Second
}

func (c ClientConfig) MouseAggregateInterval() time.Duration {
	return time.Duration(c.MouseAggregateMs) * time.Millisecond
}

func (c ClientConfig) ReconnectInitial() time.Duration {
	return time.Duration(c.Reconnect.InitialDelayMs) * time.Millisecond
}

func (c ClientConfig) ReconnectMax() time.Duration {
	return time.Duration(c.Reconnect.MaxDelayMs) * time.Millisecond
}

func boolPtr(v bool) *bool {
	return &v
}
