package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/kokukuma/oauth/gateway"
	"github.com/kokukuma/oauth/tls"
	"google.golang.org/grpc"
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
	transportCreds, err := tls.GetTransportCreds(
		fmt.Sprintf("%s/%s.crt", certs, "service1"),
		fmt.Sprintf("%s/%s.key", certs, "service1"),
		"kokukuma.service1.com",
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
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
	transportCreds, err := tls.GetTransportCreds(
		fmt.Sprintf("%s/%s.crt", certs, "service1"),
		fmt.Sprintf("%s/%s.key", certs, "service1"),
		"server.com",
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}
	opts := []grpc.DialOption{
		//grpc.WithInsecure()
		grpc.WithTransportCredentials(transportCreds),
	}
	return opts, nil
}
