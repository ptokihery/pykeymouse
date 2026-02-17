package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultHosts = "127.0.0.1,localhost"

func main() {
	var mode string
	var outDir string
	var hosts string
	var serverName string
	var days int
	var keyBits int
	var caName string
	var caKeyPath string
	var caCertPath string

	flag.StringVar(&mode, "mode", "self", "self|ca")
	flag.StringVar(&outDir, "out-dir", "certs", "output directory")
	flag.StringVar(&hosts, "hosts", defaultHosts, "comma-separated DNS or IP SANs")
	flag.StringVar(&serverName, "server-name", "pykeymouse", "server certificate common name")
	flag.IntVar(&days, "days", 825, "validity in days")
	flag.IntVar(&keyBits, "key-bits", 3072, "RSA key size")
	flag.StringVar(&caName, "ca-name", "pykeymouse-ca", "CA common name (mode=ca)")
	flag.StringVar(&caKeyPath, "ca-key", "", "existing CA key path (PEM)")
	flag.StringVar(&caCertPath, "ca-cert", "", "existing CA cert path (PEM)")
	flag.Parse()

	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "self" && mode != "ca" {
		exitf("invalid mode: %s", mode)
	}
	if keyBits < 2048 {
		exitf("key-bits must be >= 2048")
	}
	dnsNames, ipAddrs, err := parseHosts(hosts)
	if err != nil {
		exitErr(err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		exitErr(err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		exitErr(err)
	}

	serverTemplate, err := serverCertTemplate(serverName, days, dnsNames, ipAddrs)
	if err != nil {
		exitErr(err)
	}

	var caKey *rsa.PrivateKey
	var caCert *x509.Certificate
	var caCertDER []byte
	if mode == "ca" {
		if caKeyPath != "" || caCertPath != "" {
			if caKeyPath == "" || caCertPath == "" {
				exitf("both -ca-key and -ca-cert are required when using an existing CA")
			}
			caKey, caCert, err = loadCA(caKeyPath, caCertPath)
			if err != nil {
				exitErr(err)
			}
		} else {
			caKey, caCert, caCertDER, err = createAndWriteCA(outDir, caName, days)
			if err != nil {
				exitErr(err)
			}
		}
	}

	var certDER []byte
	if mode == "self" {
		certDER, err = x509.CreateCertificate(rand.Reader, serverTemplate, serverTemplate, &serverKey.PublicKey, serverKey)
		if err != nil {
			exitErr(err)
		}
	} else {
		if caKey == nil || caCert == nil {
			exitf("CA is required in mode=ca")
		}
		certDER, err = x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
		if err != nil {
			exitErr(err)
		}
	}

	serverKeyPath := filepath.Join(outDir, "server.key")
	serverCertPath := filepath.Join(outDir, "server.crt")
	if err := writeKey(serverKeyPath, serverKey); err != nil {
		exitErr(err)
	}
	if err := writeCert(serverCertPath, certDER); err != nil {
		exitErr(err)
	}

	if mode == "ca" && caCertDER != nil {
		caCertPath = filepath.Join(outDir, "ca.crt")
	}

	pin := sha256.Sum256(certDER)
	fmt.Println("Generated:")
	fmt.Printf("  server.key: %s\n", absPath(serverKeyPath))
	fmt.Printf("  server.crt: %s\n", absPath(serverCertPath))
	if mode == "ca" {
		fmt.Printf("  ca.crt:     %s\n", absPath(caCertPath))
	}
	fmt.Println()
	fmt.Printf("Server pin (SHA256 DER): %s\n", hex.EncodeToString(pin[:]))
	fmt.Println()
	fmt.Println("Server config:")
	fmt.Printf("  tls.cert_path = \"%s\"\n", absPath(serverCertPath))
	fmt.Printf("  tls.key_path  = \"%s\"\n", absPath(serverKeyPath))
	fmt.Println()
	fmt.Println("Client config:")
	if mode == "self" {
		fmt.Printf("  tls.ca_cert_path = \"%s\"\n", absPath(serverCertPath))
	} else {
		fmt.Printf("  tls.ca_cert_path = \"%s\"\n", absPath(caCertPath))
	}
	fmt.Printf("  tls.server_cert_pin_sha256 = \"%s\"  (optional)\n", hex.EncodeToString(pin[:]))
}

func serverCertTemplate(name string, days int, dns []string, ips []net.IP) (*x509.Certificate, error) {
	if len(dns) == 0 && len(ips) == 0 {
		return nil, errors.New("at least one DNS or IP SAN is required")
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dns,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}, nil
}

func createAndWriteCA(outDir, name string, days int) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)
	caTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caKeyPath := filepath.Join(outDir, "ca.key")
	caCertPath := filepath.Join(outDir, "ca.crt")
	if err := writeKey(caKeyPath, caKey); err != nil {
		return nil, nil, nil, err
	}
	if err := writeCert(caCertPath, caDER); err != nil {
		return nil, nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	return caKey, caCert, caDER, nil
}

func loadCA(keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("failed to decode CA key")
	}
	key, err := parseRSAPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, errors.New("failed to decode CA cert")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA {
		return nil, nil, errors.New("provided cert is not a CA")
	}
	return key, cert, nil
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unsupported private key type")
	}
	return rsaKey, nil
}

func writeKey(path string, key *rsa.PrivateKey) error {
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return writePEM(path, block, 0o600)
}

func writeCert(path string, certDER []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return writePEM(path, block, 0o644)
}

func writePEM(path string, block *pem.Block, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, block)
}

func parseHosts(value string) ([]string, []net.IP, error) {
	parts := strings.Split(value, ",")
	dns := make([]string, 0, len(parts))
	ips := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		host := strings.TrimSpace(part)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, host)
	}
	if len(dns) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("hosts list is empty")
	}
	return dns, ips, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func absPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func exitErr(err error) {
	exitf("%v", err)
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
