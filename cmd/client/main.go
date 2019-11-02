package main

import (
	// "crypto/tls"
	"flag"
	"log"
	"net"

	"github.com/kokukuma/oauth/client"
	"github.com/kokukuma/oauth/tls"
)

const (
	authAddr = ":10000"
	resAddr  = ":10001"
	cliAddr  = ":10002"
	domain   = "service1"
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
	tlsconfig, err := tls.GetTLSConfig(certs, domain)
	if err != nil {
		log.Fatalln(err)
	}
	ac, err := tls.GetTransportCreds(name, certs, "server.com")
	if err != nil {
		log.Fatalln(err)
	}
	rc, err := tls.GetTransportCreds(name, certs, "resource.com")
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
