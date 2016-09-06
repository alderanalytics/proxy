package router

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

func makeCertificate(host string) (cert tls.Certificate, err error) {
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := notBefore.Add(3650 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cert, fmt.Errorf("failed to generate serial number: %s", err)
	}

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              keyUsage | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return cert, fmt.Errorf("Failed to create certificate: %s", err)
	}

	certPEMBlock := pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	certPEMBytes := pem.EncodeToMemory(&certPEMBlock)

	privPemBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	keyPEMBlock := pem.EncodeToMemory(&privPemBlock)

	cert, err = tls.X509KeyPair(certPEMBytes, keyPEMBlock)
	return
}
