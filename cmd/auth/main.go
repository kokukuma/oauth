package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/kokukuma/oauth/auth"
)

const (
	// Domain is resource server's domain
	Domain   = "server.com"
	authAddr = ":10000"
)

var (
	certs = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")
)

func main() {
	flag.Parse()
	authServer("auth server", *certs)
}

func authServer(name, certs string) {
	listenPort, err := net.Listen("tcp", authAddr)
	if err != nil {
		log.Fatalln(err)
	}

	log.Print("Start grpc auth server: " + authAddr)

	tlsConfig, err := getTLSConfig(certs)
	if err != nil {
		log.Fatalln(err)
	}
	s, err := auth.NewServer(name, certs, auth.Config{
		TLSConfig:  tlsConfig,
		PublicKey:  fmt.Sprintf("%s/auth.com.crt", certs),
		PrivateKey: fmt.Sprintf("%s/auth.com.key", certs),
	})
	if err != nil {
		log.Fatalln(err)
	}
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
		// This method could not controle the restriction by gRPC method.
		// VerifyPeerCertificate: verifySANDNS,
	}
	return tlsConfig, nil
}
