package main

import (
	"flag"
	"log"
	"net"

	"github.com/kokukuma/oauth/resource"
)

const (
	resAddr = ":10001"
)

var (
	certs = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")
)

func main() {
	flag.Parse()
	resourceServer("resource server", *certs)
}

func resourceServer(name, certs string) {
	listenPort, err := net.Listen("tcp", resAddr)
	if err != nil {
		log.Fatalln(err)
	}

	log.Print("Start grpc resource server: " + resAddr)
	s := resource.NewServer(name, certs)
	s.Serve(listenPort)
}
