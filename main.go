package main

import (
	"context"
	"flag"
	"log"
	"net"

	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
	"github.com/kokukuma/oauth/client"
)

const (
	authAddr = ":10000"
	resAddr  = ":10001"
	cliAddr  = ":10002"
)

var (
	clientName = flag.String("client", "service1", "set service name")
	certs      = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")
)

func main() {
	flag.Parse()
	// client1 create token and access to resource server
	token := doCclient1()

	// client2 use token created by client1
	doCclient2(token)
}

func doCclient2(token string) {
	ctx := context.Background()
	cli, err := grpcClient(ctx, "service2", *certs)
	if err != nil {
		log.Fatal(err)
	}

	// token introspection
	res, err := cli.Introspection(ctx, token)
	log.Println("----- introspection via wrong client")
	log.Printf("active: %v", res.GetActive())
	log.Printf("clientID: %s", res.GetClientId())
	log.Printf("DNSName: %s", res.GetDnsName())
	log.Printf("X5T: %s", res.GetDnsName())

	// Verify token
	ctx = mtoken_grpc.AddTokenToContext(ctx, token)
	log.Println("----- userinfo via wrong client")
	userInfo, err := cli.UserInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(userInfo, err)
}

func doCclient1() string {
	ctx := context.Background()
	cli, err := grpcClient(ctx, "service1", *certs)
	if err != nil {
		log.Fatal(err)
	}

	// Registration
	clientID, err := cli.Regist(ctx, "service1", "kokukuma.service1.com")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("clientID: ", clientID)

	// Issue token
	token, err := cli.IssueToken(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// token introspection
	res, err := cli.Introspection(ctx, token)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("----- introspection via correct client")
	log.Printf("active: %v", res.GetActive())
	log.Printf("clientID: %s", res.GetClientId())
	log.Printf("DNSName: %s", res.GetDnsName())
	log.Printf("X5T: %s", res.GetDnsName())

	// Verify token
	ctx = mtoken_grpc.AddTokenToContext(ctx, token)
	log.Println("----- userinfo from resource server")
	userInfo, err := cli.UserInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(userInfo, err)

	return token
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

func grpcClient(ctx context.Context, name, certs string) (*client.Client, error) {
	sc, err := client.NewClient(authAddr, resAddr, name, certs)
	if err != nil {
		return nil, err
	}

	log.Print("Exec grpc client with Authorization header")

	return sc, nil
}
