package client

import "errors"

type tokenHolder struct {
	tokens map[string]string
}

func (t *tokenHolder) add(userID, token string) {
	t.tokens[userID] = token
}

func (t *tokenHolder) find(userID string) (string, error) {
	token, ok := t.tokens[userID]
	if !ok {
		return "", errors.New("no token")
	}
	return token, nil
}

func newTokenHolder() *tokenHolder {
	return &tokenHolder{
		tokens: map[string]string{},
	}
}
