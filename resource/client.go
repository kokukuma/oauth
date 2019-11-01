package resource

import (
	"context"

	resource_pb "github.com/kokukuma/oauth/resource/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client is used for connect auth service
type Client struct {
	Addr string
	Conn *grpc.ClientConn
	Cli  resource_pb.ResourceClient
}

// UserInfo gets user information from resource server
func (s *Client) UserInfo(ctx context.Context) (*resource_pb.UserInfoResponse, error) {
	message := &resource_pb.UserInfoRequest{}
	return s.Cli.UserInfo(ctx, message)
}

// ClientConfig represents client configuration.
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
		Addr: addr,
		Conn: conn,
		Cli:  resource_pb.NewResourceClient(conn),
	}
	return c, nil
}
