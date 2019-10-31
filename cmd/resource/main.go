package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/kokukuma/oauth/resource"
)

const (
	resAddr = ":10001"
	// Domain is resource server's domain
	Domain = "resource.com"
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

	tlsConfig, err := getTLSConfig(certs)
	if err != nil {
		log.Fatalln(err)
	}
	s := resource.NewServer(name, certs,
		resource.WithTLSConfig(tlsConfig),
		resource.WithAuthPublicKey(fmt.Sprintf("%s/auth.com.crt", certs)),
	)
	s.Serve(listenPort)
}

func getTLSConfig(certs string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/%s.crt", certs, Domain),
		fmt.Sprintf("%s/%s.key", certs, Domain),
	)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(fmt.Sprintf("%s/My_Root_CA.crt", certs))
	if err != nil {
		return nil, err
	}

	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, err
	}

	tlsConfig := &tls.Config{
		//ClientAuth: tls.NoClientCert,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,

		// Resource server don't need to client authentication.
		// VerifyPeerCertificate: verifySANDNS,
	}
	return tlsConfig, nil
}
