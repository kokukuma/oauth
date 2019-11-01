package auth

import (
	"context"
	"log"

	auth_pb "github.com/kokukuma/oauth/auth/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client is used for connect auth service
type Client struct {
	Name string
	Addr string
	Conn *grpc.ClientConn
	Cli  auth_pb.AuthClient
}

// Regist is used for registration of client to auth server.
func (a *Client) Regist(ctx context.Context, name, dnsName string) (string, error) {
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

// IssueToken return grpc server name.
func (a *Client) IssueToken(ctx context.Context, grantType, code, redirectURI string) (string, error) {
	message := &auth_pb.IssueTokenRequest{
		ClientId:    a.Name,
		GrantType:   grantType,
		Code:        code,
		RedirectUri: redirectURI,
	}
	res, err := a.Cli.IssueToken(ctx, message)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

// VerifyToken check the token
func (a *Client) VerifyToken(ctx context.Context) error {
	message := &auth_pb.VerifyTokenRequest{}
	_, err := a.Cli.VerifyToken(ctx, message)
	if err != nil {
		return err
	}
	return nil
}

// Introspection gets token information
func (a *Client) Introspection(ctx context.Context, token string) (*auth_pb.IntrospectiveResponse, error) {
	message := &auth_pb.IntrospectiveRequest{
		Token: token,
	}
	return a.Cli.Introspective(ctx, message)
}

// ClientConfig represents client configuration
type ClientConfig struct {
	TransportCreds credentials.TransportCredentials
}

// NewClient creates new grpc client.
func NewClient(addr, name string, config ClientConfig) (*Client, error) {
	dialOpts := []grpc.DialOption{
		//grpc.WithInsecure(),
		grpc.WithTransportCredentials(config.TransportCreds),
	}
	conn, err := grpc.Dial(addr, dialOpts...)
	if err != nil {
		return nil, err
	}
	c := &Client{
		Name: name,
		Addr: addr,
		Conn: conn,
		Cli:  auth_pb.NewAuthClient(conn),
	}
	return c, nil
}
