package jwt

import (
	"encoding/json"
	"errors"
	"net/http"
)

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

func (m *JWTMiddleware) Secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	})
}

func (m *JWTMiddleware) Auth(w http.ResponseWriter, r *http.Request) {
	var b interface{}
	err := json.NewDecoder(r.Body).Decode(&b)
	if err != nil {
		panic(err)
	}
	w.Write([]byte("test"))
}
