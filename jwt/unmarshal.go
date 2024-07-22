package jwt

const JWT = "JWT"

func Unmarshal(jws string, claims any, secret []byte) error {
	t := &token{
		payload: payload{claims: claims},
	}

	if err := t.unmarshal(jws, secret); err != nil {
		return err
	}

	if t.header.Typ != JWT {
		return UnsupportedTypeError{t.header.Typ}
	}

	return nil
}
