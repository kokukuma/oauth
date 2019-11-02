package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/kokukuma/oauth/resource"
	"github.com/kokukuma/oauth/tls"
)

const (
	resAddr = ":10001"
	domain  = "resource.com"
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

	tlsConfig, err := tls.GetTLSConfig(
		fmt.Sprintf("%s/%s.crt", certs, domain),
		fmt.Sprintf("%s/%s.key", certs, domain),
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
	if err != nil {
		log.Fatalln(err)
	}
	s := resource.NewServer(name, certs,
		resource.WithTLSConfig(tlsConfig),
		resource.WithAuthPublicKey(fmt.Sprintf("%s/auth.com.crt", certs)),
	)
	s.Serve(listenPort)
}
