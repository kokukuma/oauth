package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
	"github.com/morikuni/failure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func clientAuthUnaryServerInterceptor() grpc.UnaryServerInterceptor {

	checkCert := func(certs []*x509.Certificate, client *client) bool {
		for _, cert := range certs {
			if client.verifyDNS(cert) {
				return true
			}
		}
		return false
	}

	// Just a alternative of verifySANDNS.
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		// Don't check client auth
		if info.FullMethod == "/pb.auth.v1.Auth/Regist" {
			return handler(ctx, req)
		}

		//
		peer, ok := peer.FromContext(ctx)
		if !ok {
			return nil, errors.New("failed to get peer")
		}

		tlsInfo := peer.AuthInfo.(credentials.TLSInfo)

		for _, client := range allowedClients {
			if checkCert(tlsInfo.State.PeerCertificates, client) {
				return handler(ctx, req)
			}
		}
		return nil, errors.New("failed to checkCert")
	}
}

func errorUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		resp, err = handler(ctx, req)
		if err == nil {
			return resp, nil
		}

		// Convert gRPC error
		st := status.New(codes.Unknown, err.Error())

		if c, ok := failure.CodeOf(err); ok {
			switch c {
			case ErrInvalidToken:
				st = status.New(codes.Unauthenticated, err.Error())
			}
		}
		return resp, st.Err()
	}
}

// VerifyTokenUnaryServerInterceptor is prepared for resource server.
func VerifyTokenUnaryServerInterceptor(publicKey *rsa.PublicKey) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		// get token
		tokenStr, err := mtoken_grpc.GetTokenFromContext(ctx)
		if err != nil {
			return nil, failure.Wrap(err)
		}

		// proof-of-possession
		t := token{}
		err = mtoken_grpc.DecodeToken(ctx, tokenStr, publicKey, &t)
		if err != nil {
			return nil, failure.Translate(err, ErrInvalidToken)
		}

		if !t.verifyIss() {
			return nil, failure.Wrap(errors.New("failed to verify iss"))
		}

		return handler(ctx, req)

	}
}
