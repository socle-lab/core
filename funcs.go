package core

import "github.com/socle-lab/core/pkg/auth"

func (c *Core) GenerateApiToken(username string) (string, *auth.Payload, error) {
	tokenString, payload, err := c.Authenticator.GenerateToken(
		username,
		c.env.auth.token.exp,
		c.env.auth.token.iss,
	)

	if err != nil {
		return "", nil, err
	}
	return tokenString, payload, nil
}

func (c *Core) GenerateRefreshToken(username string) (string, *auth.Payload, error) {
	tokenString, payload, err := c.Authenticator.GenerateToken(
		username,
		c.env.auth.token.refresh,
		c.env.auth.token.iss,
	)

	if err != nil {
		return "", nil, err
	}
	return tokenString, payload, nil
}

func (c *Core) ValidateToken(token string) (*auth.Payload, error) {
	payload, err := c.Authenticator.ValidateToken(token)

	if err != nil {
		return nil, err
	}
	return payload, nil
}
