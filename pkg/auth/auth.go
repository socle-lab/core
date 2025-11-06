package auth

import (
	"time"
)

type Authenticator interface {
	GenerateToken(username string, duration time.Duration, issuer string) (string, *Payload, error)
	ValidateToken(token string) (*Payload, error)
}
