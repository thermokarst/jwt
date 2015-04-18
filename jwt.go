package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
)

var (
	ErrMissingConfig     = errors.New("missing configuration")
	ErrMissingSecret     = errors.New("please provide a shared secret")
	ErrMissingAuthFunc   = errors.New("please provide an auth function")
	ErrMissingClaimsFunc = errors.New("please provide a claims function")
	ErrEncoding          = errors.New("error encoding value")
	ErrMissingToken      = errors.New("please provide a token")
	ErrMalformedToken    = errors.New("please provide a valid token")
	ErrDecodingHeader    = errors.New("could not decode JOSE header")
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, ErrMissingToken.Error(), http.StatusUnauthorized)
			return
		}
		token := strings.Split(authHeader, " ")[1]
		if strings.LastIndex(token, ".") == -1 {
			http.Error(w, ErrMalformedToken.Error(), http.StatusUnauthorized)
			return
		}
		// Verify JOSE header
		var t struct {
			Typ string
			Alg string
		}
		tokenParts := strings.Split(token, ".")
		header, err := decode(tokenParts[0])
		if err != nil {
			log.Printf("error (%v) while decoding header (%v)", err, tokenParts[0])
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(header, &t)
		if err != nil {
			log.Printf("error (%v) while unmarshalling header (%s)", err, header)
			http.Error(w, ErrMalformedToken.Error(), http.StatusInternalServerError)
			return
		}
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

	toSig := strings.Join([]string{header, claimsSet}, ".")

	h := hmac.New(sha256.New, []byte(m.secret))
	h.Write([]byte(toSig))
	sig, err := encode(h.Sum(nil))
	if err != nil {
		panic(err)
	}

	response := strings.Join([]string{toSig, sig}, ".")
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

func decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
