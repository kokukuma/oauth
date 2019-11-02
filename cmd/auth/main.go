package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/kokukuma/oauth/auth"
	"github.com/kokukuma/oauth/tls"
)

const (
	domain   = "server.com"
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

	tlsConfig, err := tls.GetTLSConfig(
		fmt.Sprintf("%s/%s.crt", certs, domain),
		fmt.Sprintf("%s/%s.key", certs, domain),
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
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
