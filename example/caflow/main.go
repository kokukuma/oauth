package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"

	"github.com/kokukuma/oauth/auth"
	"github.com/kokukuma/oauth/ca"
	oauth_tls "github.com/kokukuma/oauth/tls"
	"google.golang.org/grpc/credentials"
)

const (
	caAddr   = ":10005"
	authAddr = ":10000"
)

var (
	certs = flag.String("certs", "/Users/kanotatsuya/go/src/github.com/square/certstrap/out", "key directory that include all key and crt files")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	pool, err := oauth_tls.GetPool(fmt.Sprintf("%s/My_Root_CA.crt", *certs))
	if err != nil {
		log.Fatal(err)
	}

	// Get certificate
	client, err := ca.NewClient(caAddr, ca.Config{
		TransportCreds: credentials.NewTLS(&tls.Config{
			ServerName: "server.com",
			RootCAs:    pool,
		}),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("---------")

	caInfo, err := client.Certificate(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// 取得したcertを使って、DialOptionつける
	crt, err := caInfo.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	// TODO: oauth_tls.GetTransportCredsだと通らなかった
	// 以下のエラーが出る. 原因をちゃんと理解できていない.
	// 2019/11/02 17:33:18 failed to regist clientrpc error: code = Unavailable desc = all SubConns are in TransientFailure, latest connection error: connection error: desc = "transport: authentication handshake failed: x509: certificate signed by unknown authority"
	// ac, err := oauth_tls.GetTransportCreds(
	// 	fmt.Sprintf("%s/%s.crt", *certs, "service1"),
	// 	fmt.Sprintf("%s/%s.key", *certs, "service1"),
	// 	"server.com", fmt.Sprintf("%s/My_Root_CA.crt", *certs))
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// register client
	// certificate, _ := tls.LoadX509KeyPair(
	// 	fmt.Sprintf("%s/%s.crt", *certs, "service1"),
	// 	fmt.Sprintf("%s/%s.key", *certs, "service1"),
	// )
	authCli, err := auth.NewClient(":10000", "service1", auth.ClientConfig{
		//TransportCreds: ac,
		TransportCreds: credentials.NewTLS(&tls.Config{
			ServerName:   "server.com",
			RootCAs:      pool,
			Certificates: []tls.Certificate{crt},
		}),
	})
	if err != nil {
		log.Fatal("failed to connect auth server", err)
	}
	clientID, err := authCli.Regist(ctx, "test", "test")
	if err != nil {
		log.Fatal("failed to regist client", err)
	}
	fmt.Println(clientID)
}
