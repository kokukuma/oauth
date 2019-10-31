package ca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	pb "github.com/kokukuma/oauth/ca/pb"
	"github.com/square/certstrap/pkix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client is used for access to CA service.
type Client struct {
	Addr string
	Conn *grpc.ClientConn
	Cli  pb.CAClient
}

// Certificate is used for creating cretificate.
// A key pair and csr are created, and request certificate to CA service.
func (c *Client) Certificate(ctx context.Context) (*caInfo, error) {
	// Create certificate request
	certInfo, err := newCertInfo()
	if err != nil {
		return nil, err
	}

	csr, err := certInfo.CSR()
	if err != nil {
		return nil, err
	}

	csrBytes, err := csr.Export()
	if err != nil {
		return nil, err
	}

	// Create certificate
	resp, err := c.Cli.Certificate(ctx, &pb.CertificateRequest{
		Csr: string(csrBytes),
	})
	if err != nil {
		return nil, err
	}

	crt, err := pkix.NewCertificateFromPEM([]byte(resp.GetCrt()))
	if err != nil {
		return nil, err
	}

	return &caInfo{
		Key: certInfo.key,
		Crt: crt,
	}, nil
}

// NewClient creates grpc client for CA server.
func NewClient(addr, certs string) (*Client, error) {

	transportCreds, err := getTransportCreds(certs, "server.com")
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
	c := &Client{
		Addr: addr,
		Conn: conn,
		Cli:  pb.NewCAClient(conn),
	}

	return c, nil
}

func getTransportCreds(certs, serverName string) (credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(fmt.Sprintf("%s/My_Root_CA.crt", certs))
	if err != nil {
		return nil, err
	}

	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, errors.New("failed to append cert to pool")
	}

	transportCreds := credentials.NewTLS(&tls.Config{
		ServerName: serverName,
		RootCAs:    certPool,
	})
	return transportCreds, nil
}
