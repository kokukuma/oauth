package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
	"github.com/kokukuma/oauth/auth"
	"github.com/kokukuma/oauth/resource"
	"google.golang.org/grpc/credentials"
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
	authCli, err := grpcAuthClient(ctx, "service2", *certs)
	if err != nil {
		log.Fatal(err)
	}

	// token introspection
	res, err := authCli.Introspection(ctx, token)
	log.Println("----- introspection via wrong client")
	log.Printf("active: %v", res.GetActive())
	log.Printf("clientID: %s", res.GetClientId())
	log.Printf("DNSName: %s", res.GetDnsName())
	log.Printf("X5T: %s", res.GetDnsName())

	// Verify token
	ctx = mtoken_grpc.AddTokenToContext(ctx, token)
	log.Println("----- userinfo via wrong client")
	resCli, err := grpcResClient(ctx, "service2", *certs)
	if err != nil {
		log.Fatal(err)
	}
	userInfo, err := resCli.UserInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(userInfo, err)
}

func doCclient1() string {
	ctx := context.Background()
	authCli, err := grpcAuthClient(ctx, "service1", *certs)
	if err != nil {
		log.Fatal(err)
	}

	// Registration
	clientID, err := authCli.Regist(ctx, "service1", "kokukuma.service1.com")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("clientID: ", clientID)

	// Issue token
	// TODO: 何故空を渡しているの...
	token, err := authCli.IssueToken(ctx, "", "", "")
	if err != nil {
		log.Fatal(err)
	}

	// token introspection
	res, err := authCli.Introspection(ctx, token)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("----- introspection via correct client")
	log.Printf("active: %v", res.GetActive())
	log.Printf("clientID: %s", res.GetClientId())
	log.Printf("DNSName: %s", res.GetDnsName())
	log.Printf("X5T: %s", res.GetDnsName())

	// Verify token
	resCli, err := grpcResClient(ctx, "service1", *certs)
	if err != nil {
		log.Fatal(err)
	}

	ctx = mtoken_grpc.AddTokenToContext(ctx, token)
	log.Println("----- userinfo from resource server")
	userInfo, err := resCli.UserInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(userInfo, err)

	return token
}

func grpcAuthClient(ctx context.Context, name, certs string) (*auth.Client, error) {
	ac, err := getTransportCreds(name, certs, "server.com")
	if err != nil {
		log.Fatalln(err)
	}
	acli, err := auth.NewClient(authAddr, name, auth.ClientConfig{
		TransportCreds: ac,
	})
	if err != nil {
		return nil, err
	}

	log.Print("Exec grpc client with Authorization header")

	return acli, nil
}

func grpcResClient(ctx context.Context, name, certs string) (*resource.Client, error) {
	rc, err := getTransportCreds(name, certs, "resource.com")
	if err != nil {
		log.Fatalln(err)
	}
	rcli, err := resource.NewClient(resAddr, name, resource.ClientConfig{
		TransportCreds: rc,
	})
	if err != nil {
		return nil, err
	}

	log.Print("Exec grpc client with Authorization header")

	return rcli, nil
}

func getTransportCreds(name, certs, serverName string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/%s.crt", certs, name),
		fmt.Sprintf("%s/%s.key", certs, name),
	)
	if err != nil {
		return nil, err
	}

	certPool, err := getPool(certs)
	if err != nil {
		return nil, err
	}

	transportCreds := credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	})
	return transportCreds, nil
}

func getPool(certs string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(fmt.Sprintf("%s/My_Root_CA.crt", certs))
	if err != nil {
		return nil, err
	}
	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, errors.New("failed to append cert to pool")
	}

	return certPool, nil
}
