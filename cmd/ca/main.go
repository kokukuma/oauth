package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/kokukuma/oauth/ca"
	"github.com/kokukuma/oauth/tls"
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
	tlsConfig, err := tls.GetTLSConfig(certs, domain)
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
