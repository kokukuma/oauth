package auth

import "crypto/x509"

var (
	allowedClients = clients{}
)

func genClientID(name string) string {
	// TODO: It should be more smart.
	return name
}

type clients []*client

func (c *clients) add(name, dnsName string) *client {
	clientID := genClientID(name)
	client := &client{
		id:      clientID,
		name:    name,
		dnsName: dnsName,
	}
	*c = append(*c, client)
	return client
}

func (c *clients) find(clientID string) *client {
	for _, client := range *c {
		if client.id == clientID {
			return client
		}
	}
	return nil
}

type client struct {
	id            string
	name          string
	dnsName       string
	publicKeyHash string
}

func (c *client) verifyDNS(cert *x509.Certificate) bool {
	for _, dnsName := range cert.DNSNames {
		if c.dnsName == dnsName {
			return true
		}
	}
	return false
}
