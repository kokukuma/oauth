package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/kokukuma/oauth/ca"
	oauth_tls "github.com/kokukuma/oauth/tls"
)

const (
	caAddr = ":10005"
	domain = "server.com"
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
	tlsConfig, err := oauth_tls.GetTLSConfig(
		fmt.Sprintf("%s/%s.crt", certs, domain),
		fmt.Sprintf("%s/%s.key", certs, domain),
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}
	tlsConfig.ClientAuth = tls.NoClientCert
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
