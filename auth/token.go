package auth

import (
	"context"
	"crypto/rsa"

	mtoken "github.com/kokukuma/mtls-token"
	mtoken_grpc "github.com/kokukuma/mtls-token/grpc"
)

const (
	// ISS is a domain
	ISS = "kokukuma.com"
)

type token struct {
	mtoken.Token
	ClientID string `json:"client_id"`
	DNSName  string `json:"dns_name"`
}

func newToken(cid, dns string) *token {
	return &token{
		Token: mtoken.Token{
			Iss: ISS,
		},
		ClientID: cid,
		DNSName:  dns,
	}
}

func decodeToken(ctx context.Context, payload string, publicKey *rsa.PublicKey) (*token, error) {
	t := token{}
	err := mtoken_grpc.DecodeToken(ctx, payload, publicKey, &t)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func (t *token) verifyIss() bool {
	if t.Iss != ISS {
		return false
	}
	return true
}

func (t *token) encode(ctx context.Context, privateKey *rsa.PrivateKey) (string, error) {
	return mtoken_grpc.IssueToken(ctx, privateKey, t)
}
