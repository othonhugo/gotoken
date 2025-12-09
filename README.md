# GoToken: A Lightweight JWT Implementation

[![Go Version](https://img.shields.io/badge/Go-1.18+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

GoToken is a robust and lightweight library for handling JSON Web Tokens (JWT) in Go. It provides a simple implementation of both JWS (RFC 7515) and JWT (RFC 7519) standards.

This library offers a lightweight, dependency-free, and easily auditable alternative. It's ideal for projects requiring a minimal, transparent, and RFC-compliant JWT implementation, or for educational purposes.

> [!CAUTION]
> This implementation is not intended for production use. It is provided for educational purposes only. _Use at your own risk._

## Features

- **Adherence to RFC Standards**: Fully implements [RFC 7515 (JSON Web Signature)](https://tools.ietf.org/html/rfc7515) for secure digital signatures and [RFC 7519 (JSON Web Token)](https://tools.ietf.org/html/rfc7519) for compact, URL-safe representation of claims.
- **Intuitive API**: Offers a straightforward API with only two core functions, `Marshal` for token creation and `Unmarshal` for token parsing and validation, simplifying integration.
- **Zero External Dependencies**: Built exclusively on the Go standard library, ensuring a lean footprint and minimizing supply chain risks.
- **Optimized and Lightweight**: Features a minimal codebase that is easy to understand, audit, and maintain, contributing to faster build times and smaller binaries.
- **HMAC Algorithm Support**: Provides secure signature capabilities with support for HMAC-SHA (HS) algorithms, including HS256, HS384, and HS512.

## Installation

```bash
go get github.com/othonhugo/gotoken
```

**Requirements:**
- Go 1.18 or higher

## Quick Start

```go
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
```

## Usage Examples

### Basic Token Creation and Validation

```go
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
}
```

### Custom Claims

You can extend the standard `Claims` struct with your own fields:

```go
type CustomClaims struct {
    gotoken.Claims
    UserID   int    `json:"user_id"`
    Role     string `json:"role"`
    IsActive bool   `json:"is_active"`
}

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
```

### Map-Based Claims

If you prefer flexibility over type safety:

```go
// Create with map
claims := map[string]interface{}{
    "sub":  "user-789",
    "exp":  time.Now().Add(1 * time.Hour).Unix(),
    "role": "user",
}

token, _ := gotoken.Marshal(header, claims, secret)

// Decode to map
var decoded map[string]interface{}
gotoken.Unmarshal(token, &decoded, secret)
```

### Different Algorithms

```go
// HS256 (HMAC-SHA256) - 32 byte signature
header := gotoken.Header{Alg: gotoken.HS256}

// HS384 (HMAC-SHA384) - 48 byte signature
header := gotoken.Header{Alg: gotoken.HS384}

// HS512 (HMAC-SHA512) - 64 byte signature
header := gotoken.Header{Alg: gotoken.HS512}
```

### Error Handling

```go
err := gotoken.Unmarshal(token, &claims, secret)

switch err {
case gotoken.ErrInvalidToken:
    // Token format is invalid
case gotoken.ErrSignatureMismatch:
    // Signature verification failed (wrong secret or tampered token)
case gotoken.ErrTokenExpired:
    // Token has expired (exp claim)
case gotoken.ErrTokenNotValidYet:
    // Token not valid yet (nbf claim)
case gotoken.ErrTokenUsedBeforeIssued:
    // Token used before issued time (iat claim)
default:
    // Other errors (JSON parsing, etc.)
}
```

## API Reference

### Types

#### `Header`
```go
type Header struct {
    Alg string `json:"alg"` // Algorithm: HS256, HS384, or HS512
    Typ string `json:"typ"` // Type: JWT (set automatically if empty)
}
```

#### `Claims`
```go
type Claims struct {
    Issuer    string `json:"iss,omitempty"` // Issuer
    Subject   string `json:"sub,omitempty"` // Subject
    Audience  string `json:"aud,omitempty"` // Audience
    ExpiresAt int64  `json:"exp,omitempty"` // Expiration time (Unix timestamp)
    NotBefore int64  `json:"nbf,omitempty"` // Not before time (Unix timestamp)
    IssuedAt  int64  `json:"iat,omitempty"` // Issued at time (Unix timestamp)
    ID        string `json:"jti,omitempty"` // JWT ID
}
```

### Functions

#### `Marshal`
```go
func Marshal(header Header, claims any, secret []byte) (string, error)
```
Creates a JWT token from the provided header, claims, and secret key.

**Parameters:**
- `header`: JWT header (algorithm and type)
- `claims`: Claims to encode (can be `Claims`, custom struct, or `map[string]any`)
- `secret`: Secret key for HMAC signing

**Returns:**
- `string`: Base64url-encoded JWT token
- `error`: Error if marshaling fails

#### `Unmarshal`
```go
func Unmarshal(jws string, claims any, secret []byte) error
```
Validates and decodes a JWT token.

**Parameters:**
- `jws`: JWT token string
- `claims`: Pointer to struct or map to receive decoded claims
- `secret`: Secret key for signature verification

**Returns:**
- `error`: `nil` if valid, specific error otherwise

### Constants

```go
const (
    HS256 = "HS256" // HMAC-SHA256
    HS384 = "HS384" // HMAC-SHA384
    HS512 = "HS512" // HMAC-SHA512
    JWT   = "JWT"   // Token type
)
```

### Errors

```go
var (
    ErrInvalidToken          error // Token format is invalid
    ErrSignatureMismatch     error // Signature verification failed
    ErrTokenExpired          error // Token has expired
    ErrTokenNotValidYet      error // Token not valid yet
    ErrTokenUsedBeforeIssued error // Token used before issued
)
```

## Security Considerations

### What This Library Does

- **Constant-time signature comparison** using `hmac.Equal()` to prevent timing attacks
- **Signature verification before claims processing** to prevent processing tampered tokens
- **Proper base64url encoding** (RFC 4648) with no padding
- **Time-based claim validation** (exp, nbf, iat)
- **Algorithm verification** to prevent algorithm substitution attacks

### What You Must Do

1. **Use Strong Secrets**: Use cryptographically random secrets of at least 32 bytes
   ```go
   secret := make([]byte, 32)
   _, err := rand.Read(secret)
   ```

2. **Validate Audience**: If using the `aud` claim, validate it in your application
   ```go
   if decoded.Audience != "your-app-name" {
       return errors.New("invalid audience")
   }
   ```

3. **Keep Secrets Secret**: Never commit secrets to version control
   
4. **Use HTTPS**: Always transmit tokens over encrypted connections

5. **Set Expiration Times**: Always set reasonable `exp` claims
   ```go
   ExpiresAt: time.Now().Add(15 * time.Minute).Unix()
   ```

6. **Rotate Secrets**: Implement secret rotation for long-running applications

## Testing

Run all tests with coverage:

```bash
go test ./... -v -cover
```

Run benchmarks:

```bash
go test ./... -bench=. -benchmem
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

**Before contributing:**
1. Ensure all tests pass (`go test ./...`)
2. Add tests for new features
3. Update documentation
4. Follow Go best practices and idioms

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 4648 - Base64 Encoding](https://tools.ietf.org/html/rfc4648)
- [jwt.io](https://jwt.io/) - JWT Debugger
