package jwt

import (
	"encoding/json"
	"errors"
	"net/http"
)

type Config struct {
	Secret string
	Auth   AuthFunc
}

type AuthFunc func(string, string) (bool, error)

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

func (m *JWTMiddleware) GenerateToken(w http.ResponseWriter, r *http.Request) {
	var b map[string]string
	err := json.NewDecoder(r.Body).Decode(&b)
	if err != nil {
		panic(err)
	}
	result, err := m.config.Auth(b["email"], b["password"])
	if err != nil {
		panic(err)
	}
	resp := "failure"
	if result {
		resp = "success"
	}
	w.Write([]byte(resp))
}
