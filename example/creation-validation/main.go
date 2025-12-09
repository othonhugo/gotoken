// Example of token creation and validation.
// nolint:all // Example code: focus on clarity over style
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/othonhugo/gotoken"
)

func main() {
	secret := []byte("secret-key")

	// Create token
	header := gotoken.Header{Alg: gotoken.HS256}
	claims := gotoken.Claims{
		Subject:   "user-456",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, _ := gotoken.Marshal(header, claims, secret)

	// Validate token
	var decoded gotoken.Claims
	err := gotoken.Unmarshal(token, &decoded, secret)
	if err != nil {
		// Token is invalid, expired, or signature doesn't match
		log.Println("Validation failed:", err)
	} else {
		fmt.Println("Token is validated:", token)
	}
}
