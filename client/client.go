package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"

	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
	pb "github.com/kokukuma/oauth/client/pb"
	"github.com/morikuni/failure"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	// Domain is resource server's domain
	Domain = "service1"

	// AuthorizationURL is the endpoint of authorization.
	AuthorizationURL = "http://localhost:8080/auth/authorization"
)

var (
	tokens = newTokenHolder()
	states = newStateHolder()
)

type clientImpl struct {
	name   string
	certs  string
	client *Client
}

func (s *clientImpl) TopPage(ctx context.Context, req *pb.TopPageRequest) (*pb.TopPageResponse, error) {

	state := createState(10)

	v := url.Values{}
	v.Set("response_type", "code")
	v.Add("scope", "test")
	v.Add("client_id", "service1")
	v.Add("redirect_uri", "http://localhost:8080/v1/callback")
	v.Add("state", state)

	states.add(state)

	authURL := fmt.Sprintf("http://localhost:8080/auth/authorization?%s", v.Encode())
	return &pb.TopPageResponse{
		Url: authURL,
	}, nil
}

func (s *clientImpl) Callback(ctx context.Context, req *pb.CallbackRequest) (*pb.CallbackResponse, error) {

	state := req.GetState()
	if !states.find(state) {
		return nil, errors.New("no state")
	}
	states.delete(state)

	token, err := s.client.IssueToken(ctx,
		WithGrantType("authorization_code"),
		WithCode(req.GetCode()),
		WithRedirectURI("http://localhost:8080/v1/callback"),
	)
	if err != nil {
		return nil, failure.Wrap(err)
	}

	userID := req.GetUserId()
	tokens.add(userID, token)

	return &pb.CallbackResponse{
		Url: fmt.Sprintf("http://localhost:8080/v1/resource/%s", userID),
	}, nil
}

func (s *clientImpl) Resource(ctx context.Context, req *pb.ResourceRequest) (*pb.ResourceResponse, error) {

	token, err := tokens.find(req.GetUserId())
	if err != nil {
		return nil, failure.Wrap(err)
	}

	ctx = mtoken_grpc.AddTokenToContext(ctx, token)
	userInfo, err := s.client.UserInfo(ctx)
	if err != nil {
		return nil, failure.Wrap(err)
	}

	return &pb.ResourceResponse{
		Email: userInfo.GetEmail(),
		Name:  userInfo.GetName(),
	}, nil
}

// New creates new sample server.
func New(name, certs string) pb.ClientServer {
	client, err := NewClient(":10000", ":10001", name, certs)
	if err != nil {
		log.Fatal(err)
	}
	clientServer := clientImpl{
		name:   name,
		certs:  certs,
		client: client,
	}
	return &clientServer
}

// NewServer creates new grpc server.
func NewServer(name, certs string) *grpc.Server {
	tlsConfig, err := getTLSConfig(certs)
	if err != nil {
		log.Fatalf("failed to get tlsConfig: %s", err)
	}
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConfig)),
	}
	server := grpc.NewServer(opts...)
	pb.RegisterClientServer(server, New(name, certs))
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

		// Unknown client cannot create tls connection.
		//VerifyPeerCertificate: verifySANDNS,
	}
	return tlsConfig, nil
}
