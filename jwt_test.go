package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("test"))
})

var authFunc = func(email, password string) error {
	return nil
}

var claimsFunc = func(id string) (map[string]interface{}, error) {
	currentTime := time.Now()
	return map[string]interface{}{
		"iat": currentTime.Unix(),
		"exp": currentTime.Add(time.Minute * 60 * 24).Unix(),
	}, nil
}

var verifyClaimsFunc = func(claims []byte, r *http.Request) error {
	currentTime := time.Now()
	var c struct {
		Exp int64
		Iat int64
	}
	err := json.Unmarshal(claims, &c)
	if err != nil {
		return err
	}
	if currentTime.After(time.Unix(c.Exp, 0)) {
		return errors.New("expired")
	}
	return nil
}

func newMiddlewareOrFatal(t *testing.T) *Middleware {
	config := &Config{
		Secret: "password",
		Auth:   authFunc,
		Claims: claimsFunc,
	}
	middleware, err := New(config)
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
	return middleware
}

func newToken(t *testing.T) (string, *Middleware) {
	middleware := newMiddlewareOrFatal(t)
	authBody := map[string]interface{}{
		"email":    "user@example.com",
		"password": "password",
	}
	body, err := json.Marshal(authBody)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewServer(middleware.Authenticate())
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Error(err)
	}
	return string(respBody), middleware
}

func TestNewJWTMiddleware(t *testing.T) {
	middleware := newMiddlewareOrFatal(t)
	if middleware.secret != "password" {
		t.Errorf("wanted password, got %v", middleware.secret)
	}
	err := middleware.auth("", "")
	if err != nil {
		t.Fatal(err)
	}
	claimsVal, err := middleware.claims("1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := claimsVal["iat"]; !ok {
		t.Errorf("wanted a claims set, got %v", claimsVal)
	}
	if middleware.identityField != "email" {
		t.Errorf("wanted email, got %v", middleware.identityField)
	}
	if middleware.verifyField != "password" {
		t.Errorf("wanted password, got %v", middleware.verifyField)
	}
}

func TestNewJWTMiddlewareNoConfig(t *testing.T) {
	cases := map[*Config]error{
		nil:       ErrMissingConfig,
		&Config{}: ErrMissingSecret,
		&Config{
			Auth:   authFunc,
			Claims: claimsFunc,
		}: ErrMissingSecret,
		&Config{
			Secret: "secret",
			Claims: claimsFunc,
		}: ErrMissingAuthFunc,
		&Config{
			Auth:   authFunc,
			Secret: "secret",
		}: ErrMissingClaimsFunc,
	}
	for config, jwtErr := range cases {
		_, err := New(config)
		if err != jwtErr {
			t.Errorf("wanted error: %v, got error: %v using config: %v", jwtErr, err, config)
		}
	}
}
func TestGenerateTokenHandler(t *testing.T) {
	token, m := newToken(t)
	j := strings.Split(token, ".")

	header := base64.StdEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"HS256"}`))
	if j[0] != header {
		t.Errorf("wanted %v, got %v", header, j[0])
	}

	claims, err := base64.StdEncoding.DecodeString(j[1])
	var c struct {
		Exp int
		Iat int
	}
	err = json.Unmarshal(claims, &c)
	if err != nil {
		t.Error(err)
	}
	duration := time.Duration(c.Exp-c.Iat) * time.Second
	d := time.Minute * 60 * 24
	if duration != d {
		t.Errorf("wanted %v, got %v", d, duration)
	}
	mac := hmac.New(sha256.New, []byte(m.secret))
	message := []byte(strings.Join([]string{j[0], j[1]}, "."))
	mac.Write(message)
	expectedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(j[2]), []byte(expectedMac)) {
		t.Errorf("wanted %v, got %v", expectedMac, j[2])
	}
}

func TestSecureHandlerNoToken(t *testing.T) {
	middleware := newMiddlewareOrFatal(t)
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	middleware.Secure(testHandler, verifyClaimsFunc).ServeHTTP(resp, req)
	body := strings.TrimSpace(resp.Body.String())
	if body != ErrMissingToken.Error() {
		t.Errorf("wanted %q, got %q", ErrMissingToken.Error(), body)
	}
}

func TestSecureHandlerBadToken(t *testing.T) {
	middleware := newMiddlewareOrFatal(t)
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", "Bearer abcdefg")
	middleware.Secure(testHandler, verifyClaimsFunc).ServeHTTP(resp, req)
	body := strings.TrimSpace(resp.Body.String())
	if body != ErrMalformedToken.Error() {
		t.Errorf("wanted %q, got %q", ErrMalformedToken.Error(), body)
	}

	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", "Bearer abcd.abcd.abcd")
	middleware.Secure(testHandler, verifyClaimsFunc).ServeHTTP(resp, req)
	body = strings.TrimSpace(resp.Body.String())
	if body != ErrMalformedToken.Error() {
		t.Errorf("wanted %q, got %q", ErrMalformedToken.Error(), body)
	}
}

func TestSecureHandlerBadSignature(t *testing.T) {
	token, middleware := newToken(t)
	parts := strings.Split(token, ".")
	token = strings.Join([]string{parts[0], parts[1], "abcd"}, ".")
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	middleware.Secure(testHandler, verifyClaimsFunc).ServeHTTP(resp, req)
	body := strings.TrimSpace(resp.Body.String())
	if body != ErrInvalidSignature.Error() {
		t.Errorf("wanted %s, got %s", ErrInvalidSignature.Error(), body)
	}
}

func TestSecureHandlerGoodToken(t *testing.T) {
	token, middleware := newToken(t)
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	middleware.Secure(testHandler, verifyClaimsFunc).ServeHTTP(resp, req)
	body := strings.TrimSpace(resp.Body.String())
	if body != "test" {
		t.Errorf("wanted %s, got %s", "test", body)
	}
}

func TestGenerateTokenHandlerNotPOST(t *testing.T) {
	middleware := newMiddlewareOrFatal(t)
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "http://example.com", nil)
	middleware.Authenticate().ServeHTTP(resp, req)
	body := strings.TrimSpace(resp.Body.String())
	if body != ErrInvalidMethod.Error() {
		t.Errorf("wanted %q, got %q", ErrInvalidMethod.Error(), body)
	}
}

func TestMalformedAuthorizationHeader(t *testing.T) {
	_, middleware := newToken(t)
	token := "hello!"
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", token) // No "Bearer " portion of header
	middleware.Secure(testHandler, verifyClaimsFunc).ServeHTTP(resp, req)
	body := strings.TrimSpace(resp.Body.String())
	if body != ErrMalformedToken.Error() {
		t.Errorf("wanted %q, got %q", ErrMalformedToken.Error(), body)
	}
}
