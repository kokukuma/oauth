package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"html/template"

	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	auth_pb "github.com/kokukuma/oauth/auth/pb"
	cli_pb "github.com/kokukuma/oauth/client/pb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	authAddr = ":10000"
	cliAddr  = ":10002"
)

// RunGateway start gateway for client server
func RunGateway(certs string) error {
	log.Print("Start gateway server: " + cliAddr)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux(
		runtime.WithForwardResponseOption(func(ctx context.Context, w http.ResponseWriter, msg proto.Message) error {
			switch v := msg.(type) {
			case *cli_pb.TopPageResponse:
				return topPage(ctx, w, v)
			case *cli_pb.CallbackResponse:
				return callback(ctx, w, v)
			case *cli_pb.ResourceResponse:
				return resource(ctx, w, v)
			case *auth_pb.AuthorizationResponse:
				return authorization(ctx, w, v)
			}
			return nil
		}),
	)

	// Access to Client
	transportCreds, err := getTransportCreds("service1", certs, "kokukuma.service1.com")
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}
	opts := []grpc.DialOption{
		//grpc.WithInsecure()
		grpc.WithTransportCredentials(transportCreds),
	}
	err = cli_pb.RegisterClientHandlerFromEndpoint(ctx, mux, cliAddr, opts)
	if err != nil {
		return err
	}

	// Access to Authorization
	transportCreds, err = getTransportCreds("service1", certs, "server.com")
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}
	opts = []grpc.DialOption{
		//grpc.WithInsecure()
		grpc.WithTransportCredentials(transportCreds),
	}
	err = auth_pb.RegisterAuthHandlerFromEndpoint(ctx, mux, authAddr, opts)
	if err != nil {
		return err
	}

	return http.ListenAndServe(":8080", mux)
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

func topPage(ctx context.Context, w http.ResponseWriter, resp *cli_pb.TopPageResponse) error {
	log.Println("/client/top")

	path := "./gateway/html/top.html"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.ParseFiles(path)
	if err != nil {
		fmt.Fprintf(w, "Unable to load template")
		return nil
	}
	t.Execute(w, resp)
	return nil
}

func callback(ctx context.Context, w http.ResponseWriter, resp *cli_pb.CallbackResponse) error {
	log.Println("/client/callback")

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("location", resp.GetUrl())
	w.WriteHeader(http.StatusFound) // 302 StatusFound
	return nil
}

func resource(ctx context.Context, w http.ResponseWriter, resp *cli_pb.ResourceResponse) error {
	log.Println("/client/resource")

	path := "./gateway/html/resource.html"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.ParseFiles(path)
	if err != nil {
		fmt.Fprintf(w, "Unable to load template")
		return nil
	}

	t.Execute(w, resp)
	return nil
}

func authorization(ctx context.Context, w http.ResponseWriter, resp *auth_pb.AuthorizationResponse) error {
	log.Println("/auth/authorization")

	v := url.Values{}
	v.Set("code", resp.GetCode())
	v.Add("state", resp.GetState())
	v.Add("user_id", resp.GetUserId())
	url := fmt.Sprintf("%s?%s", resp.GetRedirectUri(), v.Encode())

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("location", url)
	w.WriteHeader(http.StatusFound) // 302 StatusFound
	return nil
}
