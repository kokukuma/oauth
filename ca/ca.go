package ca

import (
	"context"
	"crypto/tls"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"

	pb "github.com/kokukuma/oauth/ca/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
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
func New(name string, config ServerConfig) (pb.CAServer, error) {
	ca, err := newCAInfo(
		config.PrivateKey,
		config.Certificate,
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

// ServerConfig represents server config
type ServerConfig struct {
	TLSConfig   *tls.Config
	PrivateKey  string
	Certificate string
}

// NewServer creates new grpc server.
func NewServer(name string, config ServerConfig) (*grpc.Server, error) {
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(config.TLSConfig)),
		grpc_middleware.WithUnaryServerChain(
		// // convert error
		// errorUnaryServerInterceptor(),
		),
	}
	server := grpc.NewServer(opts...)
	s, err := New(name, config)
	if err != nil {
		return nil, err
	}
	pb.RegisterCAServer(server, s)
	reflection.Register(server)
	return server, nil
}
