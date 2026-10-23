package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Host                 string
	Port                 string
	CertFile             string
	KeyFile              string
	ClientCAFile         string
	ExpectedControllerID string
}

// Server builds a read-only listener policy. TLS settings are all-or-nothing;
// plaintext is accepted only on a loopback address for the SSH-tunnel lab.
func Server(cfg Config, handler http.Handler) (*http.Server, *tls.Config, error) {
	if handler == nil {
		return nil, nil, errors.New("HTTP handler is required")
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	port := strings.TrimSpace(cfg.Port)
	if port == "" {
		port = "9000"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return nil, nil, errors.New("agent listener port is invalid")
	}
	fields := []string{cfg.CertFile, cfg.KeyFile, cfg.ClientCAFile, cfg.ExpectedControllerID}
	configured := 0
	for _, field := range fields {
		if strings.TrimSpace(field) != "" {
			configured++
		}
	}
	var tlsConfig *tls.Config
	if configured == 0 {
		if !loopback(host) {
			return nil, nil, errors.New("plaintext agent listener must use loopback")
		}
	} else {
		if configured != len(fields) {
			return nil, nil, errors.New("mTLS configuration is incomplete")
		}
		identity, err := url.Parse(cfg.ExpectedControllerID)
		if err != nil || identity.Scheme == "" || identity.Host == "" || identity.RawQuery != "" || identity.Fragment != "" {
			return nil, nil, errors.New("Controller workload identity must be an absolute URI without query or fragment")
		}
		certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load agent TLS certificate: %w", err)
		}
		caPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read Controller trust roots: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, nil, errors.New("Controller trust file contains no valid CA certificates")
		}
		expected := cfg.ExpectedControllerID
		tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    roots,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
					return errors.New("verified Controller client certificate is required")
				}
				for _, uri := range state.PeerCertificates[0].URIs {
					if uri.String() == expected {
						return nil
					}
				}
				return errors.New("Controller certificate identity does not match configured workload")
			},
		}
	}
	return &http.Server{Addr: net.JoinHostPort(host, port), Handler: handler, TLSConfig: tlsConfig}, tlsConfig, nil
}

// ReadOnlyHandler keeps a TLS listener scoped to the read-only agent surface.
func ReadOnlyHandler(next http.Handler) http.Handler {
	allowed := map[string]bool{
		"/health": true, "/status": true, "/discovery": true,
		"/assessment": true, "/plan": true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !allowed[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
