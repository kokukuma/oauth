package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"

	"google.golang.org/grpc/credentials"
)

// GetTLSConfig return tls config
func GetTLSConfig(crtpath, pubpath, rootcrt string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(crtpath, pubpath)
	if err != nil {
		return nil, err
	}

	certPool, err := GetPool(rootcrt)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		// ClientAuth: tls.NoClientCert,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,

		// Unknown client cannot create tls connection.
		//VerifyPeerCertificate: verifySANDNS,
	}
	return tlsConfig, nil
}

// GetPool return pool
func GetPool(rootcrt string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(rootcrt)
	if err != nil {
		return nil, err
	}
	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, errors.New("failed to append cert to pool")
	}

	return certPool, nil
}

// GetTransportCreds return transport credential
func GetTransportCreds(crtpath, pubpath, serverName, rootcrt string) (credentials.TransportCredentials, error) {
	tlsConfig, err := GetTLSConfig(crtpath, pubpath, rootcrt)
	if err != nil {
		return nil, err
	}
	tlsConfig.ServerName = serverName
	return credentials.NewTLS(tlsConfig), nil
}
