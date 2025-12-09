// Example of JWT algorithms
// nolint:all // Example code: focus on clarity over style
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/othonhugo/gotoken"
)

var (
	secret = []byte("your-secret-key")

	claims = gotoken.Claims{
		Issuer:    "my-app",
		Subject:   "user-123",
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
)

func main() {
	// HS256 (HMAC-SHA256) - 32 byte signature
	header256 := gotoken.Header{Alg: gotoken.HS256}

	encodeAndPrint(header256)

	// HS384 (HMAC-SHA384) - 48 byte signature
	header384 := gotoken.Header{Alg: gotoken.HS384}

	encodeAndPrint(header384)

	// HS512 (HMAC-SHA512) - 64 byte signature
	header512 := gotoken.Header{Alg: gotoken.HS512}

	encodeAndPrint(header512)
}

func encodeAndPrint(header gotoken.Header) {
	var decoded gotoken.Claims

	token, err := gotoken.Marshal(header, claims, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token (%s): %s\n", header.Alg, token)

	// Verify and decode the token
	err = gotoken.Unmarshal(token, &decoded, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Subject (%s): %s\n\n", header.Alg, decoded.Subject)
}
