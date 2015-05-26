package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

var (
	clientN   int
	directory string
	org       string
	duration  time.Duration
	rsaBits   int
)

// Usage: quicktls host1 host2 host3
// Output: ca.pem host1.cert host1.key host2.cert host2.key host3.cert host3.key
// NOTE: CA key is NEVER saved to disk, this ensures safety of the ca
func main() {
	flag.IntVar(&clientN, "clients", 0, "Number of client certificates to generate")
	flag.StringVar(&directory, "o", "", "Output directory")
	flag.StringVar(&org, "org", "QuickTLS", "Organization in the certificate")
	flag.DurationVar(&duration, "exp", 1080*24*time.Hour, "Time until Certificate expiration")
	flag.IntVar(&rsaBits, "rsa", 4096, "Number of RSA bits")
	flag.Parse()

	hosts := flag.Args()

	caFile := filepath.Join(directory, "ca.pem")
	ca, caKey, err := generateCA(caFile)
	if err != nil {
		log.Fatal(err)
	}

	for _, host := range hosts {
		hostCert := filepath.Join(directory, fmt.Sprintf("%s.cert", host))
		hostKey := filepath.Join(directory, fmt.Sprintf("%s.key", host))
		if err := generateCert([]string{host}, hostCert, hostKey, ca, caKey); err != nil {
			log.Fatal(err)
		}
	}
	for i := 0; i < clientN; i++ {
		clientCert := filepath.Join(directory, fmt.Sprintf("client-%d.cert", i))
		clientKey := filepath.Join(directory, fmt.Sprintf("client-%d.key", i))
		if err := generateClient(clientCert, clientKey, ca, caKey); err != nil {
			log.Fatal(err)
		}
	}
}

// newCertificate creates a new template
func newCertificate() *x509.Certificate {
	notBefore := time.Now()
	notAfter := notBefore.Add(duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
}

// generateCA creates a new CA certificate, saves the certificate
// and returns the x509 certificate and crypto private key. This
// private key should never be saved to disk, but rather used to
// immediately generate further certificates.
func generateCA(caFile string) (*x509.Certificate, crypto.PrivateKey, error) {
	template := newCertificate()
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign
	template.Subject.CommonName = org

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	ca, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	certOut, err := os.Create(caFile)
	if err != nil {
		return nil, nil, err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, err
	}

	return ca, priv, nil
}

// generateCert generates a new certificate for the given hosts using the
// provided certificate authority. The cert and key files are stored in the
// the provided files.
func generateCert(hosts []string, certFile, keyFile string, ca *x509.Certificate, caKey crypto.PrivateKey) error {
	template := newCertificate()
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			if template.Subject.CommonName == "" {
				template.Subject.CommonName = h
			}
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return err
	}

	return generateFromTemplate(certFile, keyFile, template, ca, priv, caKey)
}

// generateClient gnerates a new client certificate. The cert and key files are
// stored in the provided files.
func generateClient(certFile, keyFile string, ca *x509.Certificate, caKey crypto.PrivateKey) error {
	template := newCertificate()
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return err
	}

	return generateFromTemplate(certFile, keyFile, template, ca, priv, caKey)
}

// generateFromTemplate generates a certificate from the given template and signed by
// the given parent, storing the results in a certificate and key file.
func generateFromTemplate(certFile, keyFile string, template, parent *x509.Certificate, key *rsa.PrivateKey, parentKey crypto.PrivateKey) error {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return nil
}
