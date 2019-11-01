package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/kokukuma/oauth/ca"
)

const (
	caAddr = ":10005"
	// Domain is resource server's domain
	Domain = "server.com"
)

var (
	certs = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")
)

func main() {
	flag.Parse()
	newCAServer("ca server", *certs)
}

func newCAServer(name, certs string) {
	listenPort, err := net.Listen("tcp", caAddr)
	if err != nil {
		log.Fatalln(err)
	}

	log.Print("Start grpc auth server: " + caAddr)
	tlsConfig, err := getTLSConfig(certs)
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}
	s, err := ca.NewServer("ca server", ca.ServerConfig{
		TLSConfig:   tlsConfig,
		PrivateKey:  fmt.Sprintf("%s/My_Root_CA.key", certs),
		Certificate: fmt.Sprintf("%s/My_Root_CA.crt", certs),
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
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}
	return tlsConfig, nil
}
