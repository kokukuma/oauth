package ca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"

	pb "github.com/kokukuma/oauth/ca/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	// Domain is resource server's domain
	Domain = "server.com"
)

type caImpl struct {
	name string
	ca   *caInfo
}

func (s *caImpl) Certificate(ctx context.Context, req *pb.CertificateRequest) (*pb.CertificateResponse, error) {

	// Create certificate
	crt, err := s.ca.CRT([]byte(req.GetCsr()))
	if err != nil {
		return nil, err
	}

	crtBytes, err := crt.Export()
	if err != nil {
		return nil, err
	}

	resp := &pb.CertificateResponse{
		Crt: string(crtBytes),
	}
	return resp, nil
}

// New creates new sample server.
func New(name, certs string) (pb.CAServer, error) {
	ca, err := newCAInfo(
		fmt.Sprintf("%s/My_Root_CA.key", certs),
		fmt.Sprintf("%s/My_Root_CA.crt", certs),
	)
	if err != nil {
		return nil, err
	}
	caServer := caImpl{
		name: name,
		ca:   ca,
	}
	return &caServer, nil
}

// NewServer creates new grpc server.
func NewServer(name, certs string) (*grpc.Server, error) {
	tlsConfig, err := getTLSConfig(certs)
	if err != nil {
		return nil, err
	}
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc_middleware.WithUnaryServerChain(
		// // convert error
		// errorUnaryServerInterceptor(),
		),
	}
	server := grpc.NewServer(opts...)
	s, err := New(name, certs)
	if err != nil {
		return nil, err
	}
	pb.RegisterCAServer(server, s)
	reflection.Register(server)
	return server, nil
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
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}
	return tlsConfig, nil
}
