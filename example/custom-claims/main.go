// Example of custom claims
// nolint:all // Example code: focus on clarity over style
package main

import (
	"fmt"
	"time"

	"github.com/othonhugo/gotoken"
)

type CustomClaims struct {
	gotoken.Claims
	UserID   int    `json:"user_id"`
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
}

func main() {
	secret := []byte("secret-key")

	// Create token
	header := gotoken.Header{Alg: gotoken.HS256}

	// Create token with custom claims
	customClaims := CustomClaims{
		Claims: gotoken.Claims{
			Subject:   "john.doe",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
		UserID:   12345,
		Role:     "admin",
		IsActive: true,
	}

	token, _ := gotoken.Marshal(header, customClaims, secret)

	// Decode custom claims
	var decoded CustomClaims
	gotoken.Unmarshal(token, &decoded, secret)

	fmt.Printf("User ID: %d, Role: %s\n", decoded.UserID, decoded.Role)
}
