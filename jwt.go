package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var (
	ErrMissingConfig     = errors.New("missing configuration")
	ErrMissingSecret     = errors.New("please provide a shared secret")
	ErrMissingAuthFunc   = errors.New("please provide an auth function")
	ErrMissingClaimsFunc = errors.New("please provide a claims function")
	ErrEncoding          = errors.New("error encoding value")
)

type Config struct {
	Secret string
	Auth   AuthFunc
	Claims ClaimsFunc
}

type AuthFunc func(string, string) (bool, error)

type ClaimsFunc func(id string) (map[string]interface{}, error)

type JWTMiddleware struct {
	secret string
	auth   AuthFunc
	claims ClaimsFunc
}

func NewMiddleware(c *Config) (*JWTMiddleware, error) {
	if c == nil {
		return nil, ErrMissingConfig
	}
	if c.Secret == "" {
		return nil, ErrMissingSecret
	}
	if c.Auth == nil {
		return nil, ErrMissingAuthFunc
	}
	if c.Claims == nil {
		return nil, ErrMissingClaimsFunc
	}
	m := &JWTMiddleware{
		secret: c.Secret,
		auth:   c.Auth,
		claims: c.Claims,
	}
	return m, nil
}

func (m *JWTMiddleware) Secure(h http.Handler) http.Handler {
	// This is just a placeholder for now
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
	result, err := m.auth(b["email"], b["password"])
	if err != nil {
		panic(err)
	}
	if !result {
		panic("deal with this")
	}

	// For now, the header will be static
	header, err := encode(`{"typ":"JWT","alg":"HS256"}`)
	if err != nil {
		panic(err)
	}

	claims, err := m.claims(b["email"])
	if err != nil {
		panic(err)
	}

	claimsJson, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	claimsSet, err := encode(claimsJson)
	if err != nil {
		panic(err)
	}

	response := strings.Join([]string{header, claimsSet}, ".")

	w.Write([]byte(response))
}

func encode(s interface{}) (string, error) {
	var r []byte
	switch v := s.(type) {
	case string:
		r = []byte(v)
	case []byte:
		r = v
	default:
		return "", ErrEncoding
	}
	return base64.StdEncoding.EncodeToString(r), nil
}
