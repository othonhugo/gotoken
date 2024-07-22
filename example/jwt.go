package example

import "github.com/othon-hugo/go-jwt/jwt"

var SecretKey = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

type Info struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

func Marshal() any {
	h := jwt.Header{
		Alg: jwt.HS256,
		Typ: "JWT",
	}

	claims := Info{ID: 1, Username: "foobar"}

	token, err := jwt.Marshal(h, claims, SecretKey)

	if err != nil {
		return err
	}

	return token
}

func Unmarshal() any {
	token, ok := Marshal().(string)

	if !ok {
		return ok
	}

	claims := Info{}

	if err := jwt.Unmarshal(token, &claims, SecretKey); err != nil {
		return err
	}

	return claims
}
