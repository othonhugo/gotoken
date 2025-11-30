package jwt

import (
	"strings"
	"testing"
)

// TestEncodeJWTBase64 tests the base64url encoding function
func TestEncodeJWTBase64(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		check func(string) error
	}{
		{
			name:  "empty input",
			input: []byte{},
			check: func(s string) error {
				if s != "" {
					t.Errorf("expected empty string, got %q", s)
				}

				return nil
			},
		},
		{
			name:  "simple text",
			input: []byte("hello world"),
			check: func(s string) error {
				if strings.Contains(s, "=") {
					t.Error("output should not contain padding")
				}

				if strings.Contains(s, "+") || strings.Contains(s, "/") {
					t.Error("output should use URL-safe alphabet")
				}

				return nil
			},
		},
		{
			name:  "binary data producing + in standard base64",
			input: []byte{0xfb, 0xff}, // These bytes produce '+' in standard base64, '-' in base64url
			check: func(s string) error {
				if strings.Contains(s, "+") {
					t.Error("should not contain + character")
				}

				// Should use URL-safe alphabet
				return nil
			},
		},
		{
			name:  "binary data producing / in standard base64",
			input: []byte{0xff, 0xf0},
			check: func(s string) error {
				if !strings.Contains(s, "_") {
					t.Error("expected URL-safe character _")
				}

				if strings.Contains(s, "/") {
					t.Error("should not contain / character")
				}

				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeJWTBase64(tt.input)

			tt.check(result)
		})
	}
}

// TestDecodeJWTBase64 tests the base64url decoding function
func TestDecodeJWTBase64(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantBytes []byte
		wantErr   bool
	}{
		{
			name:      "empty input",
			input:     "",
			wantBytes: []byte{},
			wantErr:   false,
		},
		{
			name:      "valid URL-safe base64",
			input:     "aGVsbG8",
			wantBytes: []byte("hello"),
			wantErr:   false,
		},
		{
			name:      "URL-safe characters - and _",
			input:     "Pv8",
			wantBytes: []byte{0x3e, 0xff},
			wantErr:   false,
		},
		{
			name:    "invalid characters",
			input:   "aGVs@G8",
			wantErr: true,
		},
		{
			name:    "contains padding (should work with RawURLEncoding)",
			input:   "aGVsbG8=",
			wantErr: true, // RawURLEncoding does not accept padding
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeJWTBase64(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("decodeJWTBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(got) != string(tt.wantBytes) {
				t.Errorf("decodeJWTBase64() = %v, want %v", got, tt.wantBytes)
			}
		})
	}
}

// TestB64ValuesRoundTrip verifies encoding and decoding work together
func TestB64ValuesRoundTrip(t *testing.T) {
	original := b64values{
		header:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		payload:   "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
		signature: "XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o",
	}

	// Marshal to string
	marshaled := original.marshal()

	// Verify format
	if strings.Count(marshaled, ".") != 2 {
		t.Errorf("marshaled token should have exactly 2 dots, got %d", strings.Count(marshaled, "."))
	}

	// Unmarshal back
	var decoded b64values

	err := decoded.unmarshal(marshaled)

	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify values match
	if decoded.header != original.header {
		t.Errorf("header mismatch: got %q, want %q", decoded.header, original.header)
	}

	if decoded.payload != original.payload {
		t.Errorf("payload mismatch: got %q, want %q", decoded.payload, original.payload)
	}

	if decoded.signature != original.signature {
		t.Errorf("signature mismatch: got %q, want %q", decoded.signature, original.signature)
	}
}

// TestB64ValuesUnmarshalEdgeCases tests edge cases for unmarshal
func TestB64ValuesUnmarshalEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "no dots",
			input:   "nodots",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "one dot",
			input:   "one.dot",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "two dots (valid)",
			input:   "two.valid.dots",
			wantErr: nil,
		},
		{
			name:    "more than two dots (valid - extra dots in signature)",
			input:   "header.payload.sig.with.dots",
			wantErr: nil, // SplitN with limit 3 handles this correctly
		},
		{
			name:    "leading dot",
			input:   ".header.payload",
			wantErr: nil, // Results in empty header, which is technically invalid but caught later
		},
		{
			name:    "trailing dot",
			input:   "header.payload.",
			wantErr: nil, // Results in empty signature, which is technically invalid but caught later
		},
		{
			name:    "only dots",
			input:   "..",
			wantErr: nil, // Results in all empty parts, caught during decode
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v b64values

			err := v.unmarshal(tt.input)

			if err != tt.wantErr {
				t.Errorf("b64values.unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEncodingSymmetry verifies encode->decode->encode produces same result
func TestEncodingSymmetry(t *testing.T) {
	testData := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("ab"),
		[]byte("abc"),
		[]byte("abcd"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd},
		{0x3e, 0x3f, 0x40}, // Tests boundary characters
	}

	for i, data := range testData {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			// Encode
			encoded := encodeJWTBase64(data)

			// Decode
			decoded, err := decodeJWTBase64(encoded)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			// Compare
			if string(decoded) != string(data) {
				t.Errorf("symmetry broken: original=%v, got=%v", data, decoded)
			}

			// Re-encode
			reencoded := encodeJWTBase64(decoded)
			if reencoded != encoded {
				t.Errorf("re-encoding produced different result: original=%q, reencoded=%q", encoded, reencoded)
			}
		})
	}
}

// TestB64ValuesMarshalFormat verifies the exact format of marshaled tokens
func TestB64ValuesMarshalFormat(t *testing.T) {
	v := b64values{
		header:    "HEADER",
		payload:   "PAYLOAD",
		signature: "SIGNATURE",
	}

	result := v.marshal()
	expected := "HEADER.PAYLOAD.SIGNATURE"

	if result != expected {
		t.Errorf("marshal() = %q, want %q", result, expected)
	}
}

// TestB64ValuesPreservesDots verifies dots in components are preserved
func TestB64ValuesPreservesDots(t *testing.T) {
	// When there are more than 2 dots, SplitN ensures the signature gets all remaining parts
	input := "header.payload.sig.with.multiple.dots"

	var v b64values

	err := v.unmarshal(input)

	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if v.header != "header" {
		t.Errorf("header = %q, want %q", v.header, "header")
	}

	if v.payload != "payload" {
		t.Errorf("payload = %q, want %q", v.payload, "payload")
	}

	if v.signature != "sig.with.multiple.dots" {
		t.Errorf("signature = %q, want %q", v.signature, "sig.with.multiple.dots")
	}
}

// BenchmarkEncodeJWTBase64 benchmarks encoding performance
func BenchmarkEncodeJWTBase64(b *testing.B) {
	data := []byte("The quick brown fox jumps over the lazy dog")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = encodeJWTBase64(data)
	}
}

// BenchmarkDecodeJWTBase64 benchmarks decoding performance
func BenchmarkDecodeJWTBase64(b *testing.B) {
	encoded := encodeJWTBase64([]byte("The quick brown fox jumps over the lazy dog"))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = decodeJWTBase64(encoded)
	}
}

// BenchmarkB64ValuesMarshal benchmarks b64values marshaling
func BenchmarkB64ValuesMarshal(b *testing.B) {
	v := b64values{
		header:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		payload:   "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
		signature: "XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = v.marshal()
	}
}

// BenchmarkB64ValuesUnmarshal benchmarks b64values unmarshaling
func BenchmarkB64ValuesUnmarshal(b *testing.B) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var v b64values

		_ = v.unmarshal(token)
	}
}
