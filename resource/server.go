package resource

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/kokukuma/oauth/auth"
	"github.com/kokukuma/oauth/key"
	pb "github.com/kokukuma/oauth/resource/pb"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
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

type serverOpts struct {
	tlsConfig     *tls.Config
	authPublicKey string
}

// ServerOpts is used for setting options
type ServerOpts func(*serverOpts)

// WithTLSConfig is used for setting customo transportCreds
func WithTLSConfig(tlsConfig *tls.Config) ServerOpts {
	return func(o *serverOpts) {
		o.tlsConfig = tlsConfig
	}
}

// WithAuthPublicKey is used for setting authorizatioon public key
func WithAuthPublicKey(path string) ServerOpts {
	return func(o *serverOpts) {
		o.authPublicKey = path
	}
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
func NewServer(name, certs string, opts ...ServerOpts) *grpc.Server {
	opt := serverOpts{}
	for _, o := range opts {
		o(&opt)
	}

	publicKey, err := key.ReadRsaPublicKey(opt.authPublicKey)
	if err != nil {
		log.Fatalf("failed to get publickey: %s", err)
	}
	grpcOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(opt.tlsConfig)),
		grpc_middleware.WithUnaryServerChain(
			// convert error
			errorUnaryServerInterceptor(),

			// verify token
			auth.VerifyTokenUnaryServerInterceptor(publicKey),
		),
	}
	server := grpc.NewServer(grpcOpts...)
	pb.RegisterResourceServer(server, New(name, certs))
	reflection.Register(server)
	return server
}
