package main

import (
	"flag"
	"log"
	"net"

	"github.com/kokukuma/oauth/ca"
)

const (
	caAddr = ":10005"
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
	s, err := ca.NewServer("ca server", certs)
	if err != nil {
		log.Fatalln(err)
	}
	s.Serve(listenPort)
}
