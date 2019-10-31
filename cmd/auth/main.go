package main

import (
	"flag"
	"log"
	"net"

	"github.com/kokukuma/oauth/auth"
)

const (
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
	s, err := auth.NewServer(name, certs)
	if err != nil {
		log.Fatalln(err)
	}
	s.Serve(listenPort)
}
