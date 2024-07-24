package jwt

import (
	"github.com/othon-hugo/go-jwt/pkg/crypto"
	"github.com/othon-hugo/go-jwt/pkg/encoding"
)

type token struct {
	header  Header
	payload payload
}

func (t *token) marshal(secret []byte) (string, error) {
	signer, err := t.header.signer(secret)

	if err != nil {
		return "", err
	}

	tokenHeader, err := t.header.marshal()

	if err != nil {
		return "", err
	}

	tokenPayload, err := t.payload.marshal()

	if err != nil {
		return "", err
	}

	signingMessage := tokenHeader + "." + tokenPayload

	if _, err := signer.Write([]byte(signingMessage)); err != nil {
		return "", err
	}

	tokenSignature := encoding.EncodeJWTBase64(signer.Sum(nil))

	b64vals := b64values{
		header:    tokenHeader,
		payload:   tokenPayload,
		signature: tokenSignature,
	}

	return b64vals.marshal(), nil
}

func (t *token) unmarshal(jws string, secret []byte) error {
	b64vals := b64values{}

	if err := b64vals.unmarshal(jws); err != nil {
		return err
	}

	expectedSignature, err := encoding.DecodeJWTBase64(b64vals.signature)

	if err != nil {
		return ErrInvalidToken
	}

	if err := t.header.unmarshal(b64vals.header); err != nil {
		return err
	}

	signer, err := t.header.signer(secret)

	if err != nil {
		return err
	}

	signingMessage := b64vals.header + "." + b64vals.payload

	if _, err := signer.Write([]byte(signingMessage)); err != nil {
		return err
	}

	computedSignature := signer.Sum(nil)

	if !crypto.Equal(computedSignature, expectedSignature) {
		return ErrSignatureMismatch
	}

	return t.payload.unmarshal(b64vals.payload)
}
