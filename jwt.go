// Package jwt implements a simple, opinionated net/http-compatible middleware for
// integrating JSON Web Tokens (JWT).
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

// Errors introduced by this package.
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
	ErrInvalidMethod      = errors.New("invalid request method")
)

// AuthFunc is a type for delegating user authentication to the client-code.
type AuthFunc func(string, string) error

// ClaimsFunc is a type for delegating claims generation to the client-code.
type ClaimsFunc func(string) (map[string]interface{}, error)

// VerifyClaimsFunc is a type for processing and validating JWT claims on one
// or more routes in the client-code.
type VerifyClaimsFunc func([]byte, *http.Request) error

// Config is a container for setting up the JWT middleware.
type Config struct {
	Secret        string
	Auth          AuthFunc
	Claims        ClaimsFunc
	IdentityField string
	VerifyField   string
}

// Middleware is where we store all the specifics related to the client's
// JWT needs.
type Middleware struct {
	secret        string
	auth          AuthFunc
	claims        ClaimsFunc
	identityField string
	verifyField   string
}

// New creates a new Middleware from a user-specified configuration.
func New(c *Config) (*Middleware, error) {
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
	if c.IdentityField == "" {
		c.IdentityField = "email"
	}
	if c.VerifyField == "" {
		c.VerifyField = "password"
	}
	m := &Middleware{
		secret:        c.Secret,
		auth:          c.Auth,
		claims:        c.Claims,
		identityField: c.IdentityField,
		verifyField:   c.VerifyField,
	}
	return m, nil
}

// Secure wraps a client-specified http.Handler with a verification function,
// as well as-built in parsing of the request's JWT. This allows each handler
// to have it's own verification/validation protocol.
func (m *Middleware) Secure(h http.Handler, v VerifyClaimsFunc) http.Handler {
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
		header, err := decode(tokenParts[0])
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     err,
				message: fmt.Sprintf("decoding header (%v)", tokenParts[0]),
			}
		}
		var t struct {
			Typ string
			Alg string
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
		err = v(claimSet, r)
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

// Authenticate returns a middleware that parsing an incoming request for a JWT,
// calls the client-supplied auth function, and if successful, returns a JWT to
// the requester.
func (m *Middleware) Authenticate() http.Handler {
	generateHandler := func(w http.ResponseWriter, r *http.Request) *jwtError {
		if r.Method != "POST" {
			return &jwtError{
				status:  http.StatusBadRequest,
				err:     ErrInvalidMethod,
				message: "receiving request",
			}
		}
		var b map[string]string
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     ErrParsingCredentials,
				message: "parsing authorization",
			}
		}
		// Check if required fields are in the body
		if _, ok := b[m.identityField]; !ok {
			return &jwtError{
				status:  http.StatusBadRequest,
				err:     ErrParsingCredentials,
				message: "parsing credentials, missing identity field",
			}
		}
		if _, ok := b[m.verifyField]; !ok {
			return &jwtError{
				status:  http.StatusBadRequest,
				err:     ErrParsingCredentials,
				message: "parsing credentials, missing verify field",
			}
		}
		err = m.auth(b[m.identityField], b[m.verifyField])
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     err,
				message: "performing authorization",
			}
		}
		response, err := m.CreateToken(b[m.identityField])
		if err != nil {
			return &jwtError{
				status:  http.StatusInternalServerError,
				err:     err,
				message: response,
			}
		}
		w.Write([]byte(response))
		return nil
	}

	return errorHandler(generateHandler)
}

// CreateToken generates a token from a user's identity
func (m *Middleware) CreateToken(identity string) (string, error) {
	// For now, the header will be static
	header, err := encode(fmt.Sprintf(`{"typ":%q,"alg":%q}`, typ, alg))
	if err != nil {
		return "encoding header", ErrEncoding
	}

	// Generate claims for user
	claims, err := m.claims(identity)
	if err != nil {
		return "generating claims", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "mashalling claims", ErrEncoding
	}

	claimsSet, err := encode(claimsJSON)
	if err != nil {
		return "encoding claims", ErrEncoding
	}

	toSig := strings.Join([]string{header, claimsSet}, ".")

	h := hmac.New(sha256.New, []byte(m.secret))
	h.Write([]byte(toSig))
	sig, err := encode(h.Sum(nil))
	if err != nil {
		return "encoding signature", ErrEncoding
	}

	response := strings.Join([]string{toSig, sig}, ".")
	return response, nil
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
