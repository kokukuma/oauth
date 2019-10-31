package main

import (
	"flag"

	"github.com/kokukuma/oauth/gateway"
)

var (
	certs = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")
)

func main() {
	flag.Parse()
	gateway.RunGateway(*certs)
}
