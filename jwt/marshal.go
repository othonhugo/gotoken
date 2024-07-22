package jwt

func Marshal(header Header, claims any, secret []byte) (string, error) {
	return (&token{header: header, payload: payload{claims: claims}}).marshal(secret)
}
