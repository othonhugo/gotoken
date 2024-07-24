package jwt

import "github.com/othon-hugo/go-jwt/pkg/encoding"

type payload struct {
	claims any
}

func (p *payload) marshal() (string, error) {
	jsonClaims, err := encoding.EncodeJSON(p.claims)

	if err != nil {
		return "", err
	}

	return encoding.EncodeJWTBase64(jsonClaims), nil
}

func (p *payload) unmarshal(encodedPayload string) error {
	jsonClaims, err := encoding.DecodeJWTBase64(encodedPayload)

	if err != nil {
		return err
	}

	return encoding.DecodeJSON(jsonClaims, p.claims)
}
