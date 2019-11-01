package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/kokukuma/oauth/client"
	"google.golang.org/grpc/credentials"
)

const (
	authAddr = ":10000"
	resAddr  = ":10001"
	cliAddr  = ":10002"
	// Domain is resource server's domain
	Domain = "service1"
)

var (
	certs = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")
)

func main() {
	flag.Parse()

	clientServer("service1", *certs)
}

func clientServer(name, certs string) {
	listenPort, err := net.Listen("tcp", cliAddr)
	if err != nil {
		log.Fatalln(err)
	}

	log.Print("Start grpc client server: " + cliAddr)
	tlsconfig, err := getTLSConfig(certs)
	if err != nil {
		log.Fatalln(err)
	}
	ac, err := getTransportCreds(name, certs, "server.com")
	if err != nil {
		log.Fatalln(err)
	}
	rc, err := getTransportCreds(name, certs, "resource.com")
	if err != nil {
		log.Fatalln(err)
	}
	s := client.NewServer(name, client.Config{
		TLSConfig:              tlsconfig,
		AuthAddr:               authAddr,
		ResAddr:                resAddr,
		AuthTransportCreds:     ac,
		ResourceTransportCreds: rc,
	})
	s.Serve(listenPort)
}

func getTLSConfig(certs string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/%s.crt", certs, Domain),
		fmt.Sprintf("%s/%s.key", certs, Domain),
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

func getTransportCreds(name, certs, serverName string) (credentials.TransportCredentials, error) {
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
