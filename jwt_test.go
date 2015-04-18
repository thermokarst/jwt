package jwt

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("test"))
})

var authFunc = func(email, password string) (bool, error) {
	return true, nil
}

func newJWTMiddlewareOrFatal(t *testing.T) *JWTMiddleware {
	config := &Config{
		Secret: "password",
		Auth:   authFunc,
	}
	middleware, err := NewMiddleware(config)
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
	return middleware
}

func TestNewJWTMiddleware(t *testing.T) {
	middleware := newJWTMiddlewareOrFatal(t)
	if middleware.secret != "password" {
		t.Errorf("expected 'password', got %v", middleware.secret)
	}
	// TODO: test auth func init
}

func TestNewJWTMiddlewareNoConfig(t *testing.T) {
	cases := map[*Config]error{
		nil:                       ErrMissingConfig,
		&Config{}:                 ErrMissingSecret,
		&Config{Auth: authFunc}:   ErrMissingSecret,
		&Config{Secret: "secret"}: ErrMissingAuthFunc,
	}
	for config, jwtErr := range cases {
		_, err := NewMiddleware(config)
		if err != jwtErr {
			t.Errorf("wanted error: %v, got error: %v using config: %v", jwtErr, err, config)
		}
	}
}

func TestSecureHandler(t *testing.T) {
	middleware := newJWTMiddlewareOrFatal(t)
	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	middleware.Secure(testHandler).ServeHTTP(resp, req)
	if resp.Body.String() != "test" {
		t.Errorf("expected 'test', got %v", resp.Body.String())
	}
}

func TestGenerateTokenHandler(t *testing.T) {
	middleware := newJWTMiddlewareOrFatal(t)
	authBody := map[string]interface{}{
		"email":    "user@example.com",
		"password": "password",
	}
	body, err := json.Marshal(authBody)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(middleware.GenerateToken))
	defer ts.Close()
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Error(err)
	}
	if string(respBody) != "success" {
		t.Errorf("expected 'success', got %v", string(respBody))
	}
}
