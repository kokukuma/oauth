package main

import (
	"flag"
	"log"
	"net"

	"github.com/kokukuma/oauth/client"
)

const (
	cliAddr = ":10002"
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
	s := client.NewServer(name, certs)
	s.Serve(listenPort)
}
