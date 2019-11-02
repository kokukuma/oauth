package main

import (
	// "crypto/tls"
	"flag"
	"fmt"
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
	tlsconfig, err := tls.GetTLSConfig(
		fmt.Sprintf("%s/%s.crt", certs, domain),
		fmt.Sprintf("%s/%s.key", certs, domain),
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
	if err != nil {
		log.Fatalln(err)
	}
	ac, err := tls.GetTransportCreds(
		fmt.Sprintf("%s/%s.crt", certs, name),
		fmt.Sprintf("%s/%s.key", certs, name),
		"server.com",
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
	if err != nil {
		log.Fatalln(err)
	}
	rc, err := tls.GetTransportCreds(
		fmt.Sprintf("%s/%s.crt", certs, name),
		fmt.Sprintf("%s/%s.key", certs, name),
		"resource.com",
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
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
