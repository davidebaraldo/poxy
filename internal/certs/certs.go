// Package certs gestisce le Certificate Authority di poxy e l'emissione dei
// certificati foglia. poxy usa due CA distinte:
//
//   - Tunnel CA: firma il certificato server e i certificati client usati per
//     l'mTLS del tunnel poxy-client <-> poxy-server.
//   - MITM CA: firma i certificati foglia forgiati al volo per intercettare
//     (MITM) le connessioni TLS. Questa CA va installata come trusted root
//     sulle macchine client, altrimenti le app rifiuteranno i certificati.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA rappresenta una Certificate Authority caricata in memoria, pronta a
// firmare certificati foglia.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// LoadOrCreateCA carica una CA dai file indicati oppure, se assenti, ne genera
// una nuova e la salva su disco.
func LoadOrCreateCA(certPath, keyPath, commonName string) (*CA, error) {
	certPEM, errC := os.ReadFile(certPath)
	keyPEM, errK := os.ReadFile(keyPath)
	if errC == nil && errK == nil {
		return parseCA(certPEM, keyPEM)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"poxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return parseCA(certPEM, keyPEM)
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("certs: PEM certificato CA non valido")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("certs: PEM chiave CA non valido")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// leafOptions descrive un certificato foglia da emettere.
type leafOptions struct {
	commonName string
	dnsNames   []string
	ipAddrs    []net.IP
	serverAuth bool
	clientAuth bool
}

func (ca *CA) issueLeaf(opt leafOptions) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	var eku []x509.ExtKeyUsage
	if opt.serverAuth {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if opt.clientAuth {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opt.commonName, Organization: []string{"poxy"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, 300),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		DNSNames:              opt.dnsNames,
		IPAddresses:           opt.ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ForgeLeafPEM emette un certificato foglia per l'host indicato, firmato dalla
// MITM CA. Usato per intercettare le connessioni TLS. La cache (con limite di
// dimensione) è gestita dal chiamante lato server.
func (ca *CA) ForgeLeafPEM(host string) (certPEM, keyPEM []byte, err error) {
	opt := leafOptions{commonName: host, serverAuth: true}
	if ip := net.ParseIP(host); ip != nil {
		opt.ipAddrs = []net.IP{ip}
	} else {
		opt.dnsNames = []string{host}
	}
	return ca.issueLeaf(opt)
}

// IssueServerCert emette il certificato server del tunnel (serverAuth) con i
// SAN indicati.
func (ca *CA) IssueServerCert(commonName string, dnsNames []string, ips []net.IP) (certPEM, keyPEM []byte, err error) {
	return ca.issueLeaf(leafOptions{
		commonName: commonName,
		dnsNames:   dnsNames,
		ipAddrs:    ips,
		serverAuth: true,
	})
}

// IssueClientCert emette un certificato client del tunnel (clientAuth).
func (ca *CA) IssueClientCert(commonName string) (certPEM, keyPEM []byte, err error) {
	return ca.issueLeaf(leafOptions{commonName: commonName, clientAuth: true})
}
