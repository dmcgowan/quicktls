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
	ec        string
	keepCAKey bool
)

// Usage: quicktls host1 host2 host3
// Output: ca.pem host1.cert host1.key host2.cert host2.key host3.cert host3.key
// NOTE: CA key by default is not saved to disk, this ensures integrity of the ca
func main() {
	flag.IntVar(&clientN, "clients", 0, "Number of client certificates to generate")
	flag.StringVar(&directory, "o", "", "Output directory")
	flag.StringVar(&org, "org", "QuickTLS", "Organization in the certificate")
	flag.DurationVar(&duration, "exp", 1080*24*time.Hour, "Time until Certificate expiration")
	flag.IntVar(&rsaBits, "rsa", 2048, "Number of RSA bits")
	flag.StringVar(&ec, "ec", "", "Which elliptic curve key to use 224, 384, 521 (default to use RSA)")
	flag.BoolVar(&keepCAKey, "keep-ca-key", false, "Keep CA key to generate further certificates")
	flag.Parse()

	hosts := flag.Args()

	caFile := filepath.Join(directory, "ca.pem")
	ca, caKey, err := generateCA(caFile)
	if err != nil {
		log.Fatal(err)
	}

	if keepCAKey {
		caKeyFile := filepath.Join(directory, "ca.key")
		if err := savePrivateKey(caKey, caKeyFile); err != nil {
			log.Fatal(err)
		}
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

// newPrivateKey creates a new private key depending
// on the input flags
func newPrivateKey() (crypto.PrivateKey, error) {
	if ec != "" {
		var curve elliptic.Curve
		switch ec {
		case "224":
			curve = elliptic.P224()
		case "384":
			curve = elliptic.P384()
		case "521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("Unknown elliptic curve: %q", ec)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	}
	return rsa.GenerateKey(rand.Reader, rsaBits)
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

	priv, err := newPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.(crypto.Signer).Public(), priv)
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

	priv, err := newPrivateKey()
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

	priv, err := newPrivateKey()
	if err != nil {
		return err
	}

	return generateFromTemplate(certFile, keyFile, template, ca, priv, caKey)
}

// generateFromTemplate generates a certificate from the given template and signed by
// the given parent, storing the results in a certificate and key file.
func generateFromTemplate(certFile, keyFile string, template, parent *x509.Certificate, key crypto.PrivateKey, parentKey crypto.PrivateKey) error {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, key.(crypto.Signer).Public(), parentKey)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	return savePrivateKey(key, keyFile)
}

// savePrivateKey saves the private key to a PEM file
func savePrivateKey(key crypto.PrivateKey, keyFile string) error {
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	switch v := key.(type) {
	case *rsa.PrivateKey:
		keyBytes := x509.MarshalPKCS1PrivateKey(v)
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(v)
		if err != nil {
			return err
		}
		pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	default:
		return fmt.Errorf("Unsupport private key type: %#v", key)
	}

	return nil
}
