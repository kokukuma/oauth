package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/kokukuma/oauth/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	certs = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")

	authAddr    = ":10000"
	cliAddr     = ":10002"
	gatewayAddr = ":8080"
)

func main() {
	flag.Parse()

	//
	co, err := getCliGrpcOpts(*certs)
	if err != nil {
		log.Fatal(err)
	}

	ao, err := getAuthGrpcOpts(*certs)
	if err != nil {
		log.Fatal(err)
	}

	gateway.RunGateway(gateway.Config{
		GatewayAddr:  gatewayAddr,
		AuthAddr:     authAddr,
		AuthGrpcOpts: ao,
		CliAddr:      cliAddr,
		CliGrpcOpts:  co,
	})
}

func getCliGrpcOpts(certs string) ([]grpc.DialOption, error) {
	transportCreds, err := getTransportCreds("service1", certs, "kokukuma.service1.com")
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}
	opts := []grpc.DialOption{
		//grpc.WithInsecure()
		grpc.WithTransportCredentials(transportCreds),
	}
	return opts, nil
}

func getAuthGrpcOpts(certs string) ([]grpc.DialOption, error) {
	transportCreds, err := getTransportCreds("service1", certs, "server.com")
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}
	opts := []grpc.DialOption{
		//grpc.WithInsecure()
		grpc.WithTransportCredentials(transportCreds),
	}
	return opts, nil
}

func getTransportCreds(name, certs, serverName string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/%s.crt", certs, name),
		fmt.Sprintf("%s/%s.key", certs, name),
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
		return nil, errors.New("failed to append cert to pool")
	}

	transportCreds := credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	})
	return transportCreds, nil
}
