package jwt

import "errors"

type Config struct {
	Secret string
}

type JWTMiddleware struct {
	config Config
}

func NewMiddleware(c *Config) (*JWTMiddleware, error) {
	if c == nil {
		return nil, errors.New("missing configuration")
	}
	m := &JWTMiddleware{config: *c}
	return m, nil
}
