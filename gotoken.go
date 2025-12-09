// Package gotoken implements the JSON Web Token (JWT) standard.
package gotoken

import "github.com/othonhugo/gotoken/pkg/jwt"

const (
	// HS256 represents the HMAC-SHA256 signing algorithm.
	HS256 = jwt.HS256

	// HS384 represents the HMAC-SHA384 signing algorithm.
	HS384 = jwt.HS384

	// HS512 represents the HMAC-SHA512 signing algorithm.
	HS512 = jwt.HS512

	// JWT is the type representing a JSON Web Token.
	JWT = jwt.JWT
)

// Header represents the header of a JWT.
type Header = jwt.Header

// Claims represents the claims of a JWT.
type Claims = jwt.Claims

// Marshal encodes the JWT header and claims into a JWS.
func Marshal(header Header, claims any, secret []byte) (string, error) {
	return jwt.Marshal(header, claims, secret)
}

// Unmarshal decodes the JWS into a JWT header and claims.
func Unmarshal(jws string, claims any, secret []byte) error {
	return jwt.Unmarshal(jws, claims, secret)
}
