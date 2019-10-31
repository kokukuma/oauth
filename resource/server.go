package resource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	pb "github.com/kokukuma/oauth/resource/pb"
	"github.com/kokukuma/oauth/server"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	// Domain is resource server's domain
	Domain = "resource.com"
)

type resourceImpl struct {
	name  string
	certs string
}

func (s *resourceImpl) UserInfo(ctx context.Context, req *pb.UserInfoRequest) (*pb.UserInfoResponse, error) {
	resp := &pb.UserInfoResponse{
		Name:  "kokukuma",
		Email: "kokukuma@kokukuma.com",
	}
	return resp, nil
}

// New creates new sample server.
func New(name, certs string) pb.ResourceServer {
	resourceServer := resourceImpl{
		name:  name,
		certs: certs,
	}
	return &resourceServer
}

// NewServer creates new grpc server.
func NewServer(name, certs string) *grpc.Server {
	tlsConfig, err := getTLSConfig(certs)
	if err != nil {
		log.Fatalf("failed to get tlsConfig: %s", err)
	}

	publicKey, err := readRsaPublicKey(fmt.Sprintf("%s/auth.com.crt", certs))
	if err != nil {
		log.Fatalf("failed to get publickey: %s", err)
	}
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc_middleware.WithUnaryServerChain(
			// convert error
			errorUnaryServerInterceptor(),

			// verify token
			server.VerifyTokenUnaryServerInterceptor(publicKey),
		),
	}
	server := grpc.NewServer(opts...)
	pb.RegisterResourceServer(server, New(name, certs))
	reflection.Register(server)
	return server
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
