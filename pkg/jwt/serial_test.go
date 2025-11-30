package jwt

import (
	"testing"
	"time"
)

// TestMarshal tests the high-level Marshal function
func TestMarshal(t *testing.T) {
	secret := []byte("test-secret")

	tests := []struct {
		name    string
		header  Header
		claims  any
		wantErr bool
	}{
		{
			name: "HS256 with Claims struct",
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
			name: "HS256 without Typ (should default to JWT)",
			header: Header{
				Alg: HS256,
			},
			claims: Claims{
				Subject: "user456",
			},
			wantErr: false,
		},
		{
			name: "HS384 algorithm",
			header: Header{
				Alg: HS384,
				Typ: JWT,
			},
			claims: map[string]string{
				"sub": "user789",
			},
			wantErr: false,
		},
		{
			name: "HS512 algorithm",
			header: Header{
				Alg: HS512,
				Typ: JWT,
			},
			claims: map[string]string{
				"sub": "user000",
			},
			wantErr: false,
		},
		{
			name: "custom claims map",
			header: Header{
				Alg: HS256,
				Typ: JWT,
			},
			claims: map[string]any{
				"user_id": 12345,
				"role":    "admin",
				"active":  true,
			},
			wantErr: false,
		},
		{
			name: "nil claims",
			header: Header{
				Alg: HS256,
				Typ: JWT,
			},
			claims:  nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := Marshal(tt.header, tt.claims, secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify token is not empty
			if token == "" {
				t.Error("Marshal() returned empty token")
			}

			// Verify token structure
			parts := len(token)
			if parts == 0 {
				t.Error("Marshal() returned token with no parts")
			}
		})
	}
}

// TestUnmarshal tests the high-level Unmarshal function
func TestUnmarshal(t *testing.T) {
	secret := []byte("test-secret")

	tests := []struct {
		name         string
		setupToken   func() string
		claims       any
		wantErr      bool
		validateFunc func(*testing.T, any)
	}{
		{
			name: "valid token with Claims struct",
			setupToken: func() string {
				header := Header{Alg: HS256, Typ: JWT}
				claims := Claims{
					Subject:   "user123",
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				}
				token, _ := Marshal(header, claims, secret)
				return token
			},
			claims:  &Claims{},
			wantErr: false,
			validateFunc: func(t *testing.T, c any) {
				claims := c.(*Claims)
				if claims.Subject != "user123" {
					t.Errorf("Subject = %v, want %v", claims.Subject, "user123")
				}
			},
		},
		{
			name: "valid token with map claims",
			setupToken: func() string {
				header := Header{Alg: HS256, Typ: JWT}
				claims := map[string]any{
					"user_id": float64(12345), // JSON unmarshals numbers as float64
					"role":    "admin",
				}
				token, _ := Marshal(header, claims, secret)
				return token
			},
			claims:  &map[string]any{},
			wantErr: false,
			validateFunc: func(t *testing.T, c any) {
				claims := c.(*map[string]any)
				if (*claims)["role"] != "admin" {
					t.Errorf("role = %v, want %v", (*claims)["role"], "admin")
				}
			},
		},
		{
			name: "expired token",
			setupToken: func() string {
				header := Header{Alg: HS256, Typ: JWT}
				claims := Claims{
					ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
				}
				token, _ := Marshal(header, claims, secret)
				return token
			},
			claims:  &Claims{},
			wantErr: true, // Should fail validation
		},
		{
			name: "not valid yet (nbf in future)",
			setupToken: func() string {
				header := Header{Alg: HS256, Typ: JWT}
				claims := Claims{
					NotBefore: time.Now().Add(1 * time.Hour).Unix(), // Valid in 1 hour
				}
				token, _ := Marshal(header, claims, secret)
				return token
			},
			claims:  &Claims{},
			wantErr: true, // Should fail validation
		},
		{
			name: "wrong secret",
			setupToken: func() string {
				header := Header{Alg: HS256, Typ: JWT}
				claims := Claims{Subject: "user123"}
				token, _ := Marshal(header, claims, []byte("other-secret"))
				return token
			},
			claims:  &Claims{},
			wantErr: true, // Signature mismatch
		},
		{
			name: "invalid token format",
			setupToken: func() string {
				return "invalid.token"
			},
			claims:  &Claims{},
			wantErr: true,
		},
		{
			name: "empty token",
			setupToken: func() string {
				return ""
			},
			claims:  &Claims{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.setupToken()

			err := Unmarshal(token, tt.claims, secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validateFunc != nil {
				tt.validateFunc(t, tt.claims)
			}
		})
	}
}

// TestMarshalUnmarshalRoundTrip tests complete round-trip
func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	secret := []byte("test-secret")

	type CustomClaims struct {
		Claims
		UserID int    `json:"user_id"`
		Role   string `json:"role"`
	}

	original := CustomClaims{
		Claims: Claims{
			Issuer:    "test-issuer",
			Subject:   "user123",
			Audience:  "test-audience",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
			IssuedAt:  time.Now().Add(-1 * time.Minute).Unix(),
			ID:        "token-id-123",
		},
		UserID: 12345,
		Role:   "admin",
	}

	// Marshal
	header := Header{Alg: HS256, Typ: JWT}
	token, err := Marshal(header, original, secret)

	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal
	var decoded CustomClaims

	err = Unmarshal(token, &decoded, secret)

	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Verify all fields
	if decoded.Issuer != original.Issuer {
		t.Errorf("Issuer = %v, want %v", decoded.Issuer, original.Issuer)
	}

	if decoded.Subject != original.Subject {
		t.Errorf("Subject = %v, want %v", decoded.Subject, original.Subject)
	}

	if decoded.Audience != original.Audience {
		t.Errorf("Audience = %v, want %v", decoded.Audience, original.Audience)
	}

	if decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, original.ExpiresAt)
	}

	if decoded.NotBefore != original.NotBefore {
		t.Errorf("NotBefore = %v, want %v", decoded.NotBefore, original.NotBefore)
	}

	if decoded.IssuedAt != original.IssuedAt {
		t.Errorf("IssuedAt = %v, want %v", decoded.IssuedAt, original.IssuedAt)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID = %v, want %v", decoded.ID, original.ID)
	}

	if decoded.UserID != original.UserID {
		t.Errorf("UserID = %v, want %v", decoded.UserID, original.UserID)
	}

	if decoded.Role != original.Role {
		t.Errorf("Role = %v, want %v", decoded.Role, original.Role)
	}
}

// TestUnmarshalTypeValidation tests type header validation
func TestUnmarshalTypeValidation(t *testing.T) {
	secret := []byte("test-secret")

	t.Run("valid JWT type", func(t *testing.T) {
		header := Header{Alg: HS256, Typ: JWT}
		claims := Claims{Subject: "test"}
		token, _ := Marshal(header, claims, secret)

		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err != nil {
			t.Errorf("Unmarshal() with valid type error = %v", err)
		}
	})

	t.Run("default type should be JWT", func(t *testing.T) {
		header := Header{Alg: HS256} // No Typ specified
		claims := Claims{Subject: "test"}
		token, _ := Marshal(header, claims, secret)

		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err != nil {
			t.Errorf("Unmarshal() with default type error = %v", err)
		}
	})
}

// TestClaimerInterface tests the Claimer interface validation
func TestClaimerInterface(t *testing.T) {
	secret := []byte("test-secret")
	header := Header{Alg: HS256, Typ: JWT}

	t.Run("Claims implements Claimer and validates", func(t *testing.T) {
		claims := Claims{
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		}

		token, _ := Marshal(header, claims, secret)

		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err != nil {
			t.Errorf("Unmarshal() error = %v", err)
		}
	})

	t.Run("Claims validation fails for expired token", func(t *testing.T) {
		claims := Claims{
			ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
		}

		token, _ := Marshal(header, claims, secret)

		var decoded Claims

		err := Unmarshal(token, &decoded, secret)

		if err != ErrTokenExpired {
			t.Errorf("Unmarshal() error = %v, want %v", err, ErrTokenExpired)
		}
	})

	t.Run("custom claims without Claimer interface", func(t *testing.T) {
		type CustomClaims struct {
			UserID int `json:"user_id"`
		}

		claims := CustomClaims{UserID: 123}
		token, _ := Marshal(header, claims, secret)

		var decoded CustomClaims

		err := Unmarshal(token, &decoded, secret)

		if err != nil {
			t.Errorf("Unmarshal() error = %v", err)
		}

		if decoded.UserID != 123 {
			t.Errorf("UserID = %v, want %v", decoded.UserID, 123)
		}
	})
}

// TestMultipleAlgorithms tests all supported algorithms
func TestMultipleAlgorithms(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{Subject: "test"}

	algorithms := []string{HS256, HS384, HS512}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			header := Header{Alg: alg, Typ: JWT}

			// Marshal
			token, err := Marshal(header, claims, secret)

			if err != nil {
				t.Fatalf("Marshal() with %s error = %v", alg, err)
			}

			// Unmarshal
			var decoded Claims

			err = Unmarshal(token, &decoded, secret)

			if err != nil {
				t.Errorf("Unmarshal() with %s error = %v", alg, err)
			}

			if decoded.Subject != claims.Subject {
				t.Errorf("Subject = %v, want %v", decoded.Subject, claims.Subject)
			}
		})
	}
}

// BenchmarkMarshalClaims benchmarks marshaling with Claims struct
func BenchmarkMarshalClaims(b *testing.B) {
	secret := []byte("test-secret")
	header := Header{Alg: HS256, Typ: JWT}
	claims := Claims{
		Issuer:    "test-issuer",
		Subject:   "user123",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = Marshal(header, claims, secret)
	}
}

// BenchmarkUnmarshalClaims benchmarks unmarshaling with Claims struct
func BenchmarkUnmarshalClaims(b *testing.B) {
	secret := []byte("test-secret")
	header := Header{Alg: HS256, Typ: JWT}
	claims := Claims{
		Issuer:    "test-issuer",
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

// BenchmarkMarshalMap benchmarks marshaling with map claims
func BenchmarkMarshalMap(b *testing.B) {
	secret := []byte("test-secret")
	header := Header{Alg: HS256, Typ: JWT}
	claims := map[string]any{
		"iss": "test-issuer",
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = Marshal(header, claims, secret)
	}
}

// BenchmarkUnmarshalMap benchmarks unmarshaling with map claims
func BenchmarkUnmarshalMap(b *testing.B) {
	secret := []byte("test-secret")
	header := Header{Alg: HS256, Typ: JWT}
	claims := map[string]any{
		"iss": "test-issuer",
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token, _ := Marshal(header, claims, secret)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var decoded map[string]any

		_ = Unmarshal(token, &decoded, secret)
	}
}
