package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"google.golang.org/grpc/credentials"
)

func GetTLSConfig(certs, domain string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/%s.crt", certs, domain),
		fmt.Sprintf("%s/%s.key", certs, domain),
	)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(fmt.Sprintf("%s/My_Root_CA.crt", certs))
	if err != nil {
		return nil, err
	}

	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, err
	}

	tlsConfig := &tls.Config{
		//ClientAuth: tls.NoClientCert,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,

		// Unknown client cannot create tls connection.
		//VerifyPeerCertificate: verifySANDNS,
	}
	return tlsConfig, nil
}

func GetTransportCreds(name, certs, serverName string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/%s.crt", certs, name),
		fmt.Sprintf("%s/%s.key", certs, name),
	)
	if err != nil {
		return nil, err
	}

	certPool, err := getPool(certs)
	if err != nil {
		return nil, err
	}

	transportCreds := credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	})
	return transportCreds, nil
}

func getPool(certs string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(fmt.Sprintf("%s/My_Root_CA.crt", certs))
	if err != nil {
		return nil, err
	}
	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, errors.New("failed to append cert to pool")
	}

	return certPool, nil
}
