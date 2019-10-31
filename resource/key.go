package resource

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/morikuni/failure"
)

func readRsaPublicKey(certPath string) (*rsa.PublicKey, error) {
	bytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, failure.Wrap(err)
	}
	block, _ := pem.Decode(bytes)
	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, failure.Wrap(err)
	}
	return cert.PublicKey.(*rsa.PublicKey), nil
}

func readRsaPrivateKey(pemFile string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, failure.Wrap(err)
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("invalid private key data")
	}

	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, failure.Wrap(err)
		}
	} else if block.Type == "PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, failure.Wrap(err)
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, failure.Wrap(errors.New("not RSA private key"))
		}
	} else {
		return nil, failure.Wrap(fmt.Errorf("invalid private key type : %s", block.Type))
	}

	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, failure.Wrap(err)
	}

	return key, nil
}
