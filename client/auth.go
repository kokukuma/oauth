package client

import (
	"context"
	"log"

	auth_pb "github.com/kokukuma/oauth/auth/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// AuthClient is used for connect auth service
type AuthClient struct {
	Addr string
	Conn *grpc.ClientConn
	Cli  auth_pb.AuthClient
}

// Regist is used for registration of client to auth server.
func (a *AuthClient) Regist(ctx context.Context, name, dnsName string) (string, error) {
	log.Println(name, dnsName)
	resp, err := a.Cli.Regist(ctx, &auth_pb.RegistRequest{
		Name:                name,
		TlsClientAuthSanDns: dnsName,
	})
	log.Println(resp, err)
	if err != nil {
		return "", err
	}
	return resp.GetClientId(), nil
}

type authClientOpts struct {
	transportCreds credentials.TransportCredentials
}

// AuthClientOpts is used for setting options
type AuthClientOpts func(*authClientOpts)

// WithTransportCreds is used for setting customo transportCreds
func WithTransportCreds(creds credentials.TransportCredentials) AuthClientOpts {
	return func(o *authClientOpts) {
		o.transportCreds = creds
	}
}

// NewAuthClient creates new grpc client.
func NewAuthClient(addr, name, certsDir string, opts ...AuthClientOpts) (*AuthClient, error) {
	creds, err := getTransportCreds(name, certsDir, "server.com")
	if err != nil {
		return nil, err
	}

	opt := authClientOpts{
		transportCreds: creds,
	}
	for _, o := range opts {
		o(&opt)
	}

	dialOpts := []grpc.DialOption{
		//grpc.WithInsecure(),
		grpc.WithTransportCredentials(opt.transportCreds),
	}
	conn, err := grpc.Dial(addr, dialOpts...)
	if err != nil {
		return nil, err
	}
	c := &AuthClient{
		Addr: addr,
		Conn: conn,
		Cli:  auth_pb.NewAuthClient(conn),
	}
	return c, nil
}
