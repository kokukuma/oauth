package auth

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"

	"github.com/google/uuid"
	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
	pb "github.com/kokukuma/oauth/auth/pb"
	"github.com/kokukuma/oauth/key"
	"github.com/morikuni/failure"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var (
	authorizationCode = map[string]*authCode{}
)

type authCode struct {
	code        string
	clientID    string
	redirectURI string
}

type authImpl struct {
	name       string
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	certs      string
}

func (s *authImpl) Authorization(ctx context.Context, req *pb.AuthorizationRequest) (*pb.AuthorizationResponse, error) {
	if req.GetResponseType() != "code" {
		return nil, failure.Wrap(errors.New("Unsupported grant"))
	}
	// TODO: 認証
	userID := "1"

	// create code
	u, err := uuid.NewRandom()
	if err != nil {
		return nil, failure.Wrap(errors.New("failed to create uuid"))
	}
	code := u.String()

	authorizationCode[code] = &authCode{
		code:        code,
		clientID:    req.GetClientId(),
		redirectURI: req.GetRedirectUri(),
	}

	return &pb.AuthorizationResponse{
		Code:        code,
		State:       req.GetState(),
		UserId:      userID,
		RedirectUri: req.GetRedirectUri(),
	}, nil
}

func (s *authImpl) IssueToken(ctx context.Context, req *pb.IssueTokenRequest) (*pb.IssueTokenResponse, error) {
	if req.GetCode() != "" {
		ac, ok := authorizationCode[req.GetCode()]
		if !ok {
			return nil, failure.Wrap(errors.New("failed to get code"))
		}
		if ac.clientID != req.GetClientId() {
			return nil, failure.Wrap(errors.New("invalid client ID"))
		}
		if ac.redirectURI != req.GetRedirectUri() {
			return nil, failure.Wrap(errors.New("invalid redirect URI"))
		}
	}

	client := allowedClients.find(req.GetClientId())
	if client == nil {
		return nil, failure.Wrap(errors.New("could not found client"))
	}

	token := newToken(client.id, client.dnsName)
	tokenStr, err := token.encode(ctx, s.privateKey)
	if err != nil {
		return nil, failure.Wrap(err)
	}

	resp := &pb.IssueTokenResponse{
		Token: tokenStr,
	}
	return resp, nil
}

func (s *authImpl) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	tokenStr, err := mtoken_grpc.GetTokenFromContext(ctx)
	if err != nil {
		return nil, failure.Wrap(err)
	}

	_, err = decodeToken(ctx, tokenStr, s.publicKey)
	if err != nil {
		return nil, failure.Translate(err, ErrInvalidToken)
	}

	resp := &pb.VerifyTokenResponse{
		Result: true,
	}
	return resp, nil
}

func (s *authImpl) Introspective(ctx context.Context, req *pb.IntrospectiveRequest) (*pb.IntrospectiveResponse, error) {
	payload := req.GetToken()

	// verify token
	t, err := decodeToken(ctx, payload, s.publicKey)
	if err != nil {
		return nil, failure.Wrap(err)
	}

	active := true
	resp := &pb.IntrospectiveResponse{
		Active:   active,
		DnsName:  t.DNSName,
		ClientId: t.ClientID,
		X5T:      t.Cnf.X5T,
	}
	return resp, nil
}

func (s *authImpl) Regist(ctx context.Context, req *pb.RegistRequest) (*pb.RegistResponse, error) {

	// regist client
	client := allowedClients.add(req.GetName(), req.GetTlsClientAuthSanDns())

	resp := &pb.RegistResponse{
		ClientId:            client.id,
		Name:                client.name,
		TlsClientAuthSanDns: client.dnsName,
	}
	return resp, nil
}

// New creates new sample server.
func New(name, pub, priv string) (pb.AuthServer, error) {
	publicKey, err := key.ReadRsaPublicKey(pub)
	if err != nil {
		return nil, err
	}
	privateKey, err := key.ReadRsaPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	authServer := authImpl{
		name:       name,
		publicKey:  publicKey,
		privateKey: privateKey,
	}
	return &authServer, nil
}

// Config represents auth server configuration
type Config struct {
	TLSConfig  *tls.Config
	PublicKey  string
	PrivateKey string
}

// NewServer creates new grpc server.
func NewServer(name string, config Config) (*grpc.Server, error) {
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(config.TLSConfig)),
		grpc_middleware.WithUnaryServerChain(
			// authentication of authz server
			clientAuthUnaryServerInterceptor(),

			// convert error
			errorUnaryServerInterceptor(),
		),
	}
	server := grpc.NewServer(opts...)
	s, err := New(name, config.PublicKey, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	pb.RegisterAuthServer(server, s)
	reflection.Register(server)
	return server, nil
}

// verifySANDNS is used for client authentication on TLS level.
func verifySANDNS(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}
	for _, cert := range certs {
		for _, client := range allowedClients {
			if client.verifyDNS(cert) {
				return nil
			}
		}
	}
	s := fmt.Sprintf("This domain is not in white list: %v", certs[0].DNSNames)
	log.Print(s)
	return errors.New(s)
}
