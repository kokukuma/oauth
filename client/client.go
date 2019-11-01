package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/url"

	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
	"github.com/kokukuma/oauth/auth"
	pb "github.com/kokukuma/oauth/client/pb"
	"github.com/kokukuma/oauth/resource"
	"github.com/morikuni/failure"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	// AuthorizationURL is the endpoint of authorization.
	AuthorizationURL = "http://localhost:8080/auth/authorization"
)

var (
	tokens = newTokenHolder()
	states = newStateHolder()
)

type clientImpl struct {
	name     string
	auth     *auth.Client
	resource *resource.Client
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

	token, err := s.auth.IssueToken(ctx,
		"authorization_code",
		req.GetCode(),
		"http://localhost:8080/v1/callback",
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
	userInfo, err := s.resource.UserInfo(ctx)
	if err != nil {
		return nil, failure.Wrap(err)
	}

	return &pb.ResourceResponse{
		Email: userInfo.GetEmail(),
		Name:  userInfo.GetName(),
	}, nil
}

// New creates new sample server.
func New(name string, config Config) pb.ClientServer {
	auth, err := auth.NewClient(config.AuthAddr, name, auth.ClientConfig{
		TransportCreds: config.AuthTransportCreds,
	})
	if err != nil {
		log.Fatal(err)
	}
	resource, err := resource.NewClient(config.ResAddr, name, resource.ClientConfig{
		TransportCreds: config.ResourceTransportCreds,
	})
	if err != nil {
		log.Fatal(err)
	}

	clientServer := clientImpl{
		name:     name,
		auth:     auth,
		resource: resource,
	}
	return &clientServer
}

// Config represents client configuration
type Config struct {
	TLSConfig              *tls.Config
	AuthAddr               string
	ResAddr                string
	AuthTransportCreds     credentials.TransportCredentials
	ResourceTransportCreds credentials.TransportCredentials
}

// NewServer creates new grpc server.
func NewServer(name string, config Config) *grpc.Server {
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(config.TLSConfig)),
	}
	server := grpc.NewServer(opts...)
	pb.RegisterClientServer(server, New(name, config))
	reflection.Register(server)
	return server
}
