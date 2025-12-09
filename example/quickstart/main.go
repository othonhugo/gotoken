// Quickstart example for gotoken
// nolint:all // Example code: focus on clarity over style
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/othonhugo/gotoken"
)

func main() {
	secret := []byte("your-secret-key")

	// Create a token
	header := gotoken.Header{
		Alg: gotoken.HS256,
		Typ: gotoken.JWT,
	}

	claims := gotoken.Claims{
		Issuer:    "my-app",
		Subject:   "user-123",
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token, err := gotoken.Marshal(header, claims, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Token:", token)

	// Verify and decode the token
	var decoded gotoken.Claims
	err = gotoken.Unmarshal(token, &decoded, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Subject: %s\n", decoded.Subject)
}
