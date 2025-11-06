package auth

import (
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTAuthenticator struct {
	secret string
	aud    string
	iss    string
}

func NewJWTAuthenticator(secret, aud, iss string) *JWTAuthenticator {
	return &JWTAuthenticator{secret, iss, aud}
}

func (a *JWTAuthenticator) GenerateToken(username string, duration time.Duration, issuer string) (string, *Payload, error) {

	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", payload, err
	}

	claims := jwt.MapClaims{
		"sub": username,
		"exp": payload.ExpiredAt.Unix(),
		"iat": payload.IssuedAt.Unix(),
		"nbf": payload.IssuedAt.Unix(),
		"iss": issuer,
		"aud": issuer,
		"id":  payload.ID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(a.secret))
	if err != nil {
		return "", payload, err
	}

	return tokenString, payload, nil
}

// func (a *JWTAuthenticator) ValidateToken(token string) (*jwt.Token, error) {
// 	return jwt.Parse(token, func(t *jwt.Token) (any, error) {
// 		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
// 		}

// 		return []byte(a.secret), nil
// 	},
// 		jwt.WithExpirationRequired(),
// 		jwt.WithAudience(a.aud),
// 		jwt.WithIssuer(a.aud),
// 		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
// 	)
// }

func (a *JWTAuthenticator) ValidateToken(token string) (*Payload, error) {
	// Fonction de validation du type de méthode de signature
	keyFunc := func(t *jwt.Token) (any, error) {
		if err := validateSigningMethod(t); err != nil {
			return nil, err
		}
		return []byte(a.secret), nil
	}

	jwtToken, err := jwt.Parse(token, keyFunc,
		jwt.WithExpirationRequired(),
		jwt.WithAudience(a.aud),
		jwt.WithIssuer(a.aud),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if err != nil {
		return nil, err
	}
	claims, _ := jwtToken.Claims.(jwt.MapClaims)

	iat, err := strconv.ParseInt(fmt.Sprintf("%.f", claims["iat"]), 10, 64)
	if err != nil {
		return nil, err
	}
	exp, err := strconv.ParseInt(fmt.Sprintf("%.f", claims["exp"]), 10, 64)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("**********************   %v     **************************\n", claims)
	//uuid.Must(uuid.Parse(fmt.Sprintf("%.f", claims["id"])))
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	return &Payload{
		ID:        tokenID,
		Username:  fmt.Sprintf("%s", claims["sub"]),
		IssuedAt:  time.Unix(iat, 0),
		ExpiredAt: time.Unix(exp, 0),
	}, nil
}

// Fonction séparée pour valider la méthode de signature
func validateSigningMethod(t *jwt.Token) error {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		return fmt.Errorf("unexpected signing method %v", t.Header["alg"])
	}
	return nil
}
