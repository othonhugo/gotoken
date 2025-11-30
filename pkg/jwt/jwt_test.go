package jwt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestBase64URLEncoding verifies RFC 7515 compliance for base64url encoding
func TestBase64URLEncoding(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty byte slice",
			input: []byte{},
			want:  "",
		},
		{
			name:  "standard ASCII",
			input: []byte("hello"),
			want:  "aGVsbG8",
		},
		{
			name:  "bytes that produce + in standard base64",
			input: []byte{0xFB, 0xFF},
			want:  "-_8", // Should use - instead of +
		},
		{
			name:  "bytes that produce / in standard base64",
			input: []byte{0xFF, 0xFF},
			want:  "__8", // Should use _ instead of /
		},
		{
			name:  "no padding characters",
			input: []byte("hello!"),
			want:  "aGVsbG8h", // No trailing =
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeJWTBase64(tt.input)

			if got != tt.want {
				t.Errorf("encodeJWTBase64() = %v, want %v", got, tt.want)
			}

			// Verify no padding
			if strings.Contains(got, "=") {
				t.Errorf("encodeJWTBase64() contains padding character '='")
			}

			// Verify URL-safe (no + or /)
			if strings.Contains(got, "+") || strings.Contains(got, "/") {
				t.Errorf("encodeJWTBase64() contains non-URL-safe characters (+ or /)")
			}

			// Verify round-trip
			decoded, err := decodeJWTBase64(got)

			if err != nil {
				t.Errorf("decodeJWTBase64() error = %v", err)
			}

			if string(decoded) != string(tt.input) {
				t.Errorf("round-trip failed: got %v, want %v", decoded, tt.input)
			}
		})
	}
}

// TestBase64URLDecoding verifies decoding compliance
func TestBase64URLDecoding(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty string",
			input:   "",
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "URL-safe characters with hyphen",
			input:   "-_8",
			want:    []byte{0xFB, 0xFF},
			wantErr: false,
		},
		{
			name:    "URL-safe characters with underscore",
			input:   "__8",
			want:    []byte{0xFF, 0xFF},
			wantErr: false,
		},
		{
			name:    "standard ASCII",
			input:   "aGVsbG8",
			want:    []byte("hello"),
			wantErr: false,
		},
		{
			name:    "invalid base64 character",
			input:   "aGVs@G8",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeJWTBase64(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("decodeJWTBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("decodeJWTBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestB64ValuesMarshaling verifies JWS Compact Serialization format
func TestB64ValuesMarshaling(t *testing.T) {
	tests := []struct {
		name   string
		values b64values
		want   string
	}{
		{
			name: "standard JWT structure",
			values: b64values{
				header:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				payload:   "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
				signature: "signature",
			},
			want: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		},
		{
			name: "empty components",
			values: b64values{
				header:    "",
				payload:   "",
				signature: "",
			},
			want: "..",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.values.marshal()

			if got != tt.want {
				t.Errorf("b64values.marshal() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestB64ValuesUnmarshaling verifies JWT structure validation
func TestB64ValuesUnmarshaling(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    b64values
		wantErr error
	}{
		{
			name:  "valid JWT with 3 parts",
			input: "header.payload.signature",
			want: b64values{
				header:    "header",
				payload:   "payload",
				signature: "signature",
			},
			wantErr: nil,
		},
		{
			name:  "JWT with dots in components",
			input: "head.er.pay.load.sig.nature",
			want: b64values{
				header:    "head",
				payload:   "er",
				signature: "pay.load.sig.nature",
			},
			wantErr: nil,
		},
		{
			name:    "invalid JWT with 2 parts",
			input:   "header.payload",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "invalid JWT with 1 part",
			input:   "token",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got b64values

			err := got.unmarshal(tt.input)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("b64values.unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("b64values.unmarshal() unexpected error = %v", err)
				return
			}

			if got.header != tt.want.header || got.payload != tt.want.payload || got.signature != tt.want.signature {
				t.Errorf("b64values.unmarshal() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestHeaderMarshaling verifies header JSON encoding
func TestHeaderMarshaling(t *testing.T) {
	tests := []struct {
		name    string
		header  Header
		wantErr bool
	}{
		{
			name: "HS256 header",
			header: Header{
				Alg: HS256,
				Typ: JWT,
			},
			wantErr: false,
		},
		{
			name: "HS384 header",
			header: Header{
				Alg: HS384,
				Typ: JWT,
			},
			wantErr: false,
		},
		{
			name: "HS512 header",
			header: Header{
				Alg: HS512,
				Typ: JWT,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.header.marshal()

			if (err != nil) != tt.wantErr {
				t.Errorf("Header.marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify no padding
			if strings.Contains(encoded, "=") {
				t.Errorf("Header.marshal() contains padding")
			}

			// Verify round-trip
			var decoded Header

			if err := decoded.unmarshal(encoded); err != nil {
				t.Errorf("Header.unmarshal() error = %v", err)
				return
			}

			if decoded.Alg != tt.header.Alg || decoded.Typ != tt.header.Typ {
				t.Errorf("Header round-trip failed: got %+v, want %+v", decoded, tt.header)
			}
		})
	}
}

// TestHeaderSigner verifies algorithm to hash function mapping
func TestHeaderSigner(t *testing.T) {
	secret := []byte("secret")

	tests := []struct {
		name     string
		alg      string
		wantErr  bool
		hashSize int // expected hash output size in bytes
	}{
		{
			name:     "HS256",
			alg:      HS256,
			wantErr:  false,
			hashSize: 32, // SHA-256 = 32 bytes
		},
		{
			name:     "HS384",
			alg:      HS384,
			wantErr:  false,
			hashSize: 48, // SHA-384 = 48 bytes
		},
		{
			name:     "HS512",
			alg:      HS512,
			wantErr:  false,
			hashSize: 64, // SHA-512 = 64 bytes
		},
		{
			name:     "lowercase hs256",
			alg:      "hs256",
			wantErr:  false,
			hashSize: 32,
		},
		{
			name:    "unsupported algorithm RS256",
			alg:     "RS256",
			wantErr: true,
		},
		{
			name:    "unsupported algorithm ES256",
			alg:     "ES256",
			wantErr: true,
		},
		{
			name:    "empty algorithm",
			alg:     "",
			wantErr: true,
		},
		{
			name:    "invalid algorithm",
			alg:     "INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Alg: tt.alg}

			signer, err := h.signer(secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("Header.signer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify hash size
			signer.Write([]byte("test"))
			hash := signer.Sum(nil)

			if len(hash) != tt.hashSize {
				t.Errorf("Hash size = %d bytes, want %d bytes", len(hash), tt.hashSize)
			}
		})
	}
}

// TestPayloadMarshaling verifies payload encoding
func TestPayloadMarshaling(t *testing.T) {
	tests := []struct {
		name    string
		claims  any
		wantErr bool
	}{
		{
			name: "simple claims",
			claims: map[string]any{
				"sub":  "1234567890",
				"name": "John Doe",
			},
			wantErr: false,
		},
		{
			name: "Claims struct",
			claims: Claims{
				Subject:   "user123",
				ExpiresAt: time.Now().Unix(),
			},
			wantErr: false,
		},
		{
			name:    "nil claims",
			claims:  nil,
			wantErr: false,
		},
		{
			name: "nested claims",
			claims: map[string]any{
				"user": map[string]any{
					"id":   123,
					"name": "John",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := payload{claims: tt.claims}

			encoded, err := p.marshal()

			if (err != nil) != tt.wantErr {
				t.Errorf("payload.marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify no padding
			if strings.Contains(encoded, "=") {
				t.Errorf("payload.marshal() contains padding")
			}

			// Verify URL-safe
			if strings.Contains(encoded, "+") || strings.Contains(encoded, "/") {
				t.Errorf("payload.marshal() contains non-URL-safe characters")
			}
		})
	}
}

// TestClaimsValidation verifies RFC 7519 claims validation
func TestClaimsValidation(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name: "valid claims with future expiration",
			claims: Claims{
				ExpiresAt: now + 3600, // 1 hour in future
			},
			wantErr: nil,
		},
		{
			name: "expired token (exp = now)",
			claims: Claims{
				ExpiresAt: now,
			},
			wantErr: ErrTokenExpired,
		},
		{
			name: "expired token (exp in past)",
			claims: Claims{
				ExpiresAt: now - 3600,
			},
			wantErr: ErrTokenExpired,
		},
		{
			name: "not valid yet (nbf in future)",
			claims: Claims{
				NotBefore: now + 3600,
			},
			wantErr: ErrTokenNotValidYet,
		},
		{
			name: "valid nbf (nbf = now)",
			claims: Claims{
				NotBefore: now,
			},
			wantErr: nil,
		},
		{
			name: "valid nbf (nbf in past)",
			claims: Claims{
				NotBefore: now - 3600,
			},
			wantErr: nil,
		},
		{
			name: "used before issued (iat in future)",
			claims: Claims{
				IssuedAt: now + 3600,
			},
			wantErr: ErrTokenUsedBeforeIssued,
		},
		{
			name: "valid iat (iat = now)",
			claims: Claims{
				IssuedAt: now,
			},
			wantErr: nil,
		},
		{
			name: "valid iat (iat in past)",
			claims: Claims{
				IssuedAt: now - 3600,
			},
			wantErr: nil,
		},
		{
			name: "all claims valid",
			claims: Claims{
				Issuer:    "test-issuer",
				Subject:   "user-123",
				Audience:  "test-audience",
				ExpiresAt: now + 3600,
				NotBefore: now - 60,
				IssuedAt:  now - 60,
				ID:        "jwt-id-123",
			},
			wantErr: nil,
		},
		{
			name:    "zero values (all optional)",
			claims:  Claims{},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Valid()

			if err != tt.wantErr {
				t.Errorf("Claims.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestTokenMarshalUnmarshal verifies end-to-end token creation and validation
func TestTokenMarshalUnmarshal(t *testing.T) {
	secret := []byte("test-secret-key-123")

	tests := []struct {
		name    string
		header  Header
		claims  Claims
		wantErr bool
	}{
		{
			name: "HS256 with valid claims",
			header: Header{
				Alg: HS256,
				Typ: JWT,
			},
			claims: Claims{
				Subject:   "user123",
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErr: false,
		},
		{
			name: "HS384 with valid claims",
			header: Header{
				Alg: HS384,
				Typ: JWT,
			},
			claims: Claims{
				Subject: "user456",
			},
			wantErr: false,
		},
		{
			name: "HS512 with valid claims",
			header: Header{
				Alg: HS512,
				Typ: JWT,
			},
			claims: Claims{
				Subject: "user789",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal token
			tokenString, err := Marshal(tt.header, tt.claims, secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify structure: header.payload.signature
			parts := strings.Split(tokenString, ".")

			if len(parts) != 3 {
				t.Errorf("Token has %d parts, want 3", len(parts))
			}

			// Verify no padding in any part
			for i, part := range parts {
				if strings.Contains(part, "=") {
					t.Errorf("Token part %d contains padding", i)
				}
			}

			// Unmarshal token
			var decoded Claims

			err = Unmarshal(tokenString, &decoded, secret)

			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify claims match
			if decoded.Subject != tt.claims.Subject {
				t.Errorf("Subject = %v, want %v", decoded.Subject, tt.claims.Subject)
			}

			if decoded.ExpiresAt != tt.claims.ExpiresAt {
				t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, tt.claims.ExpiresAt)
			}
		})
	}
}

// TestSignatureVerification verifies signature validation
func TestSignatureVerification(t *testing.T) {
	secret := []byte("secret")
	wrongSecret := []byte("wrong-secret")

	header := Header{Alg: HS256, Typ: JWT}
	claims := Claims{Subject: "test"}

	// Create a valid token
	token, err := Marshal(header, claims, secret)

	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	t.Run("valid signature", func(t *testing.T) {
		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err != nil {
			t.Errorf("Unmarshal() with correct secret error = %v", err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		var decoded Claims

		err := Unmarshal(token, &decoded, wrongSecret)

		if err != ErrSignatureMismatch {
			t.Errorf("Unmarshal() with wrong secret error = %v, want %v", err, ErrSignatureMismatch)
		}
	})

	t.Run("tampered token", func(t *testing.T) {
		parts := strings.Split(token, ".")

		// Tamper with payload
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"hacker"}`))
		tamperedToken := strings.Join(parts, ".")

		var decoded Claims

		err := Unmarshal(tamperedToken, &decoded, secret)

		if err != ErrSignatureMismatch {
			t.Errorf("Unmarshal() with tampered token error = %v, want %v", err, ErrSignatureMismatch)
		}
	})

	t.Run("tampered header", func(t *testing.T) {
		parts := strings.Split(token, ".")

		// Tamper with header
		parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		tamperedToken := strings.Join(parts, ".")

		var decoded Claims

		err := Unmarshal(tamperedToken, &decoded, secret)

		if err == nil {
			t.Error("Unmarshal() with tampered header should fail")
		}
	})
}

// TestConstantTimeComparison verifies timing attack resistance
func TestConstantTimeComparison(t *testing.T) {
	secret := []byte("secret")
	header := Header{Alg: HS256, Typ: JWT}
	claims := Claims{Subject: "test"}

	token, _ := Marshal(header, claims, secret)

	// This test verifies that hmac.Equal is used
	// We can't easily test timing, but we verify the behavior is correct
	secrets := [][]byte{
		[]byte("wrong1"),
		[]byte("wrong2"),
		[]byte("wrong3"),
		secret,
	}

	for i, testSecret := range secrets {
		var decoded Claims

		err := Unmarshal(token, &decoded, testSecret)

		if i < len(secrets)-1 {
			// Wrong secrets should fail
			if err != ErrSignatureMismatch {
				t.Errorf("Test %d: expected ErrSignatureMismatch, got %v", i, err)
			}
		} else {
			// Correct secret should succeed
			if err != nil {
				t.Errorf("Test %d: expected success, got %v", i, err)
			}
		}
	}
}

// TestTypeHeaderValidation verifies "typ" header validation
func TestTypeHeaderValidation(t *testing.T) {
	secret := []byte("secret")
	claims := Claims{Subject: "test"}

	tests := []struct {
		name    string
		typ     string
		wantErr bool
	}{
		{
			name:    "valid JWT type",
			typ:     JWT,
			wantErr: false,
		},
		{
			name:    "default typ (should be set to JWT)",
			typ:     "",
			wantErr: false,
		},
		{
			name:    "invalid type",
			typ:     "INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := Header{
				Alg: HS256,
				Typ: tt.typ,
			}

			token, err := Marshal(header, claims, secret)

			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			var decoded Claims

			err = Unmarshal(token, &decoded, secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCustomClaimsWithValidation verifies custom claims with validation
func TestCustomClaimsWithValidation(t *testing.T) {
	secret := []byte("secret")
	header := Header{Alg: HS256, Typ: JWT}

	type CustomClaims struct {
		Claims
		CustomField string `json:"custom_field"`
	}

	claims := CustomClaims{
		Claims: Claims{
			Subject:   "test",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		},
		CustomField: "custom-value",
	}

	token, err := Marshal(header, claims, secret)

	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded CustomClaims

	err = Unmarshal(token, &decoded, secret)

	if err != nil {
		t.Errorf("Unmarshal() error = %v", err)
		return
	}

	if decoded.CustomField != claims.CustomField {
		t.Errorf("CustomField = %v, want %v", decoded.CustomField, claims.CustomField)
	}

	if decoded.Subject != claims.Subject {
		t.Errorf("Subject = %v, want %v", decoded.Subject, claims.Subject)
	}
}

// TestEdgeCases verifies edge case handling
func TestEdgeCases(t *testing.T) {
	secret := []byte("secret")

	t.Run("empty secret", func(t *testing.T) {
		header := Header{Alg: HS256, Typ: JWT}
		claims := Claims{Subject: "test"}

		token, err := Marshal(header, claims, []byte{})

		if err != nil {
			t.Errorf("Marshal() with empty secret error = %v", err)
		}

		var decoded Claims

		err = Unmarshal(token, &decoded, []byte{})

		if err != nil {
			t.Errorf("Unmarshal() with empty secret error = %v", err)
		}
	})

	t.Run("very long secret", func(t *testing.T) {
		longSecret := make([]byte, 10000)

		for i := range longSecret {
			longSecret[i] = byte(i % 256)
		}

		header := Header{Alg: HS256, Typ: JWT}
		claims := Claims{Subject: "test"}

		token, err := Marshal(header, claims, longSecret)

		if err != nil {
			t.Errorf("Marshal() with long secret error = %v", err)
		}

		var decoded Claims

		err = Unmarshal(token, &decoded, longSecret)

		if err != nil {
			t.Errorf("Unmarshal() with long secret error = %v", err)
		}
	})

	t.Run("malformed token - missing signature", func(t *testing.T) {
		token := "header.payload"

		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err != ErrInvalidToken {
			t.Errorf("Unmarshal() error = %v, want %v", err, ErrInvalidToken)
		}
	})

	t.Run("malformed token - invalid base64", func(t *testing.T) {
		token := "header!.payload.signature"

		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err == nil {
			t.Error("Unmarshal() should fail with invalid base64")
		}
	})

	t.Run("malformed token - invalid JSON in header", func(t *testing.T) {
		invalidHeader := base64.RawURLEncoding.EncodeToString([]byte("{invalid json}"))
		token := invalidHeader + ".payload.signature"

		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err == nil {
			t.Error("Unmarshal() should fail with invalid JSON in header")
		}
	})
}

// BenchmarkMarshal benchmarks token creation
func BenchmarkMarshal(b *testing.B) {
	secret := []byte("secret")
	header := Header{Alg: HS256, Typ: JWT}
	claims := Claims{
		Subject:   "user123",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = Marshal(header, claims, secret)
	}
}

// BenchmarkUnmarshal benchmarks token validation
func BenchmarkUnmarshal(b *testing.B) {
	secret := []byte("secret")
	header := Header{Alg: HS256, Typ: JWT}
	claims := Claims{
		Subject:   "user123",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, _ := Marshal(header, claims, secret)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var decoded Claims

		_ = Unmarshal(token, &decoded, secret)
	}
}

// BenchmarkBase64URLEncode benchmarks base64url encoding
func BenchmarkBase64URLEncode(b *testing.B) {
	data := []byte("The quick brown fox jumps over the lazy dog")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = encodeJWTBase64(data)
	}
}

// BenchmarkBase64URLDecode benchmarks base64url decoding
func BenchmarkBase64URLDecode(b *testing.B) {
	encoded := encodeJWTBase64([]byte("The quick brown fox jumps over the lazy dog"))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = decodeJWTBase64(encoded)
	}
}
