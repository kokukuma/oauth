package ca

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/url"
	"time"

	"github.com/square/certstrap/pkix"
)

type cert struct {
	key *pkix.Key
	csr *pkix.CertificateSigningRequest
	crt *pkix.Certificate
}

type certInfo struct {
	key                *pkix.Key
	organizationalUnit string
	organization       string
	country            string
	province           string
	locality           string
	commonName         string
	ipList             []net.IP
	domainList         []string
	uriList            []*url.URL
}

func newCertInfo() (*certInfo, error) {
	// TODO: What parameter should be set?
	key, err := pkix.CreateRSAKey(1024)
	if err != nil {
		return nil, err
	}
	return &certInfo{
		key: key,
	}, nil
}

func (c *certInfo) CSR() (*pkix.CertificateSigningRequest, error) {
	return pkix.CreateCertificateSigningRequest(
		c.key,
		c.organizationalUnit,
		c.ipList,
		c.domainList,
		c.uriList,
		c.organization,
		c.country,
		c.province,
		c.locality,
		c.commonName)
}

type caInfo struct {
	Key *pkix.Key
	Crt *pkix.Certificate
}

func newCAInfo(keyPath, certPath string) (*caInfo, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := pkix.NewKeyFromPrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, err
	}
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	crt, err := pkix.NewCertificateFromPEM(certBytes)
	if err != nil {
		return nil, err
	}
	return &caInfo{
		Key: key,
		Crt: crt,
	}, nil
}

// CRT creates certificate from certificate request..
func (c *caInfo) CRT(bytes []byte) (*pkix.Certificate, error) {
	csr, err := pkix.NewCertificateSigningRequestFromPEM(bytes)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return pkix.CreateCertificateHost(c.Crt, c.Key, csr, now.Add(365*24*time.Hour))
}

func (c *caInfo) TLSCertificate() (tls.Certificate, error) {
	var cert tls.Certificate

	crt, err := c.Crt.Export()
	if err != nil {
		return cert, err
	}
	key, err := c.Key.ExportPrivate()
	if err != nil {
		return cert, err
	}

	cert, err = tls.X509KeyPair(crt, key)
	if err != nil {
		return cert, err
	}

	return cert, nil
}
