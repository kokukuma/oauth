package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	auth_pb "github.com/kokukuma/oauth/auth/pb"
	resource_pb "github.com/kokukuma/oauth/resource/pb"
	"google.golang.org/grpc/credentials"
)

// Client replisent Auth client.
type Client struct {
	clientID string
	auth     *AuthClient
	resource *ResourceClient
}

type issueTokenOpts struct {
	grantType   string
	code        string
	redirectURI string
	clientID    string
}

// IssueTokenOpts is used for setting option of issue token.
type IssueTokenOpts func(*issueTokenOpts)

// WithGrantType is for adding grant type
func WithGrantType(grantType string) IssueTokenOpts {
	return func(o *issueTokenOpts) {
		o.grantType = grantType
	}
}

// WithCode is for adding code
func WithCode(code string) IssueTokenOpts {
	return func(o *issueTokenOpts) {
		o.code = code
	}
}

// WithRedirectURI is for adding redirect uri
func WithRedirectURI(redirectURI string) IssueTokenOpts {
	return func(o *issueTokenOpts) {
		o.redirectURI = redirectURI
	}
}

// IssueToken return grpc server name.
func (s *Client) IssueToken(ctx context.Context, opts ...IssueTokenOpts) (string, error) {
	opt := issueTokenOpts{
		clientID: s.clientID,
	}
	for _, o := range opts {
		o(&opt)
	}

	message := &auth_pb.IssueTokenRequest{
		ClientId:    s.clientID,
		GrantType:   opt.grantType,
		Code:        opt.code,
		RedirectUri: opt.redirectURI,
	}
	res, err := s.auth.Cli.IssueToken(ctx, message)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

// VerifyToken check the token
func (s *Client) VerifyToken(ctx context.Context) error {
	message := &auth_pb.VerifyTokenRequest{}
	_, err := s.auth.Cli.VerifyToken(ctx, message)
	if err != nil {
		return err
	}
	return nil
}

// Introspection gets token information
func (s *Client) Introspection(ctx context.Context, token string) (*auth_pb.IntrospectiveResponse, error) {
	message := &auth_pb.IntrospectiveRequest{
		Token: token,
	}
	return s.auth.Cli.Introspective(ctx, message)
}

// Regist is used for registration client
func (s *Client) Regist(ctx context.Context, name, dnsName string) (string, error) {
	return s.auth.Regist(ctx, name, dnsName)
}

// UserInfo gets user information from resource server
func (s *Client) UserInfo(ctx context.Context) (*resource_pb.UserInfoResponse, error) {
	message := &resource_pb.UserInfoRequest{}
	return s.resource.Cli.UserInfo(ctx, message)
}

// Close method close the grpc connection.
func (s *Client) Close() error {
	s.auth.Conn.Close()
	s.resource.Conn.Close()
	return nil
}

// NewClient create sample client.
func NewClient(authAddr, resAddr, name, certs string) (*Client, error) {
	auth, err := NewAuthClient(authAddr, name, certs)
	if err != nil {
		return nil, err
	}
	resource, err := NewResourceClient(resAddr, name, certs)
	if err != nil {
		return nil, err
	}
	return &Client{
		clientID: name,
		auth:     auth,
		resource: resource,
	}, nil
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
