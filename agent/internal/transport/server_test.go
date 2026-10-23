package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPlaintextIsLoopbackOnlyAndTLSSettingsAreAllOrNothing(t *testing.T) {
	if _, _, err := Server(Config{Host: "0.0.0.0"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
		t.Fatal("non-loopback plaintext listener accepted")
	}
	if _, _, err := Server(Config{Host: "127.0.0.1", CertFile: "cert"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
		t.Fatal("partial TLS configuration accepted")
	}
	if _, tlsConfig, err := Server(Config{Host: "127.0.0.1"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err != nil || tlsConfig != nil {
		t.Fatalf("loopback lab HTTP config: tls=%v err=%v", tlsConfig, err)
	}
}

func TestMutualTLSReadOnlyHandlerVerifiesControllerIdentity(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caDER := makeTestCA(t)
	agentPEM, agentKey := makeLeaf(t, caCert, caKey, "agent", "spiffe://lab/agent/a1", true)
	controllerPEM, controllerKey := makeLeaf(t, caCert, caKey, "controller", "spiffe://lab/controller/c1", false)
	wrongPEM, wrongKey := makeLeaf(t, caCert, caKey, "wrong", "spiffe://lab/controller/other", false)
	certPath, keyPath := writeKeyPair(t, dir, "agent", agentPEM, agentKey)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	server, _, err := Server(Config{
		Host: "127.0.0.1", Port: "0", CertFile: certPath, KeyFile: keyPath,
		ClientCAFile: caPath, ExpectedControllerID: "spiffe://lab/controller/c1",
	}, ReadOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		<-done
	})

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	request := func(clientPEM, clientKey []byte) error {
		var certificates []tls.Certificate
		if len(clientPEM) > 0 {
			cert, err := tls.X509KeyPair(clientPEM, clientKey)
			if err != nil {
				return err
			}
			certificates = []tls.Certificate{cert}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: "127.0.0.1", Certificates: certificates,
		}}}
		defer client.CloseIdleConnections()
		response, err := client.Get("https://" + listener.Addr().String() + "/status")
		if err == nil {
			_ = response.Body.Close()
		}
		return err
	}
	if err := request(controllerPEM, controllerKey); err != nil {
		t.Fatalf("valid mTLS request rejected: %v", err)
	}
	if err := request(wrongPEM, wrongKey); err == nil {
		t.Fatal("client certificate with wrong workload URI was accepted")
	}
	if err := request(nil, nil); err == nil {
		t.Fatal("connection without a Controller client certificate was accepted")
	}
	cert, err := tls.X509KeyPair(controllerPEM, controllerKey)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{cert},
	}}}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + listener.Addr().String() + "/execute")
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("mTLS execute path status=%d, want 404", response.StatusCode)
	}
}

func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, der
}

func makeLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name, uri string, server bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsedURI, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(name) + 10)),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		URIs: []*url.URL{parsedURI}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeKeyPair(t *testing.T, dir, name string, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
