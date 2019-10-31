package client

import (
	"log"

	resource_pb "github.com/kokukuma/oauth/resource/pb"
	"google.golang.org/grpc"
)

// ResourceClient is used for connect auth service
type ResourceClient struct {
	Addr string
	Conn *grpc.ClientConn
	Cli  resource_pb.ResourceClient
}

// NewResourceClient creates new grpc client.
func NewResourceClient(addr, name, certsDir string) (*ResourceClient, error) {

	transportCreds, err := getTransportCreds(name, certsDir, "resource.com")
	if err != nil {
		log.Fatalf("failed to get transportCreds: %s", err)
	}

	dialOpts := []grpc.DialOption{
		//grpc.WithInsecure(),
		grpc.WithTransportCredentials(transportCreds),
	}
	conn, err := grpc.Dial(addr, dialOpts...)
	if err != nil {
		return nil, err
	}
	c := &ResourceClient{
		Addr: addr,
		Conn: conn,
		Cli:  resource_pb.NewResourceClient(conn),
	}
	return c, nil
}
