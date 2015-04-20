package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

const (
	typ = "JWT"
	alg = "HS256"
)

var (
	ErrMissingConfig      = errors.New("missing configuration")
	ErrMissingSecret      = errors.New("please provide a shared secret")
	ErrMissingAuthFunc    = errors.New("please provide an auth function")
	ErrMissingClaimsFunc  = errors.New("please provide a claims function")
	ErrEncoding           = errors.New("error encoding value")
	ErrDecoding           = errors.New("error decoding value")
	ErrMissingToken       = errors.New("please provide a token")
	ErrMalformedToken     = errors.New("please provide a valid token")
	ErrInvalidSignature   = errors.New("signature could not be verified")
	ErrParsingCredentials = errors.New("error parsing credentials")
)

type Config struct {
	Secret string
	Auth   AuthFunc
	Claims ClaimsFunc
}

type AuthFunc func(string, string) error

type ClaimsFunc func(string) (map[string]interface{}, error)

type VerifyClaimsFunc func([]byte) error

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

type jwtError struct {
	status  int
	err     error
	message string
}

type errorHandler func(http.ResponseWriter, *http.Request) *jwtError

func (e errorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := e(w, r); err != nil {
		if err.message != "" {
			log.Printf("error (%v) while %s", err.err, err.message)
		}
		http.Error(w, err.err.Error(), err.status)
	}
}

func (m *JWTMiddleware) Secure(h http.Handler, v VerifyClaimsFunc) http.Handler {
	secureHandler := func(w http.ResponseWriter, r *http.Request) *jwtError {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return &jwtError{status: http.StatusUnauthorized, err: ErrMissingToken}
		}
		token := strings.Split(authHeader, " ")[1]
		tokenParts := strings.Split(token, ".")
		if len(tokenParts) != 3 {
			return &jwtError{status: http.StatusUnauthorized, err: ErrMalformedToken}
		}

		// First, verify JOSE header
		var t struct {
			Typ string
			Alg string
		}
		header, err := decode(tokenParts[0])
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     err,
				message: fmt.Sprintf("decoding header (%v)", tokenParts[0]),
			}
		}
		err = json.Unmarshal(header, &t)
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrMalformedToken,
				message: fmt.Sprintf("unmarshalling header (%s)", header),
			}
		}

		// Then, verify signature
		mac := hmac.New(sha256.New, []byte(m.secret))
		message := []byte(strings.Join([]string{tokenParts[0], tokenParts[1]}, "."))
		mac.Write(message)
		expectedMac, err := encode(mac.Sum(nil))
		if err != nil {
			return &jwtError{status: http.StatusInternalServerError, err: err}
		}
		if !hmac.Equal([]byte(tokenParts[2]), []byte(expectedMac)) {
			return &jwtError{
				status:  http.StatusUnauthorized,
				err:     ErrInvalidSignature,
				message: fmt.Sprintf("checking signature (%v)", tokenParts[2]),
			}
		}

		// Finally, check claims
		claimSet, err := decode(tokenParts[1])
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrDecoding,
				message: "decoding claims",
			}
		}
		err = v(claimSet)
		if err != nil {
			return &jwtError{
				status:  http.StatusUnauthorized,
				err:     err,
				message: "handling claims callback",
			}
		}

		// If we make it this far, process the downstream handler
		h.ServeHTTP(w, r)
		return nil
	}

	return errorHandler(secureHandler)
}

func (m *JWTMiddleware) GenerateToken() http.Handler {
	generateHandler := func(w http.ResponseWriter, r *http.Request) *jwtError {
		var b map[string]string
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrParsingCredentials,
				message: "parsing authorization",
			}
		}
		err = m.auth(b["email"], b["password"])
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     err,
				message: "performing authorization",
			}
		}

		// For now, the header will be static
		header, err := encode(fmt.Sprintf(`{"typ":%q,"alg":%q}`, typ, alg))
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrEncoding,
				message: "encoding header",
			}
		}

		// Generate claims for user
		claims, err := m.claims(b["email"])
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     err,
				message: "generating claims",
			}
		}

		claimsJson, err := json.Marshal(claims)
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrEncoding,
				message: "marshalling claims",
			}
		}

		claimsSet, err := encode(claimsJson)
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrEncoding,
				message: "encoding claims",
			}
		}

		toSig := strings.Join([]string{header, claimsSet}, ".")

		h := hmac.New(sha256.New, []byte(m.secret))
		h.Write([]byte(toSig))
		sig, err := encode(h.Sum(nil))
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrEncoding,
				message: "encoding signature",
			}
		}

		response := strings.Join([]string{toSig, sig}, ".")
		w.Write([]byte(response))
		return nil
	}

	return errorHandler(generateHandler)
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
