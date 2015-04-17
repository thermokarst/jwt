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

func newJWTMiddlewareOrFatal(t *testing.T) *JWTMiddleware {
	config := &Config{
		Secret: "password",
	}
	middleware, err := NewMiddleware(config)
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
	return middleware
}

func TestNewJWTMiddleware(t *testing.T) {
	middleware := newJWTMiddlewareOrFatal(t)
	if middleware.config.Secret != "password" {
		t.Errorf("expected 'password', got %v", middleware.config.Secret)
	}
}

func TestNewJWTMiddlewareNoConfig(t *testing.T) {
	_, err := NewMiddleware(nil)
	if err == nil {
		t.Error("expected configuration error, received none")
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

func TestAuthHandler(t *testing.T) {
	middleware := newJWTMiddlewareOrFatal(t)
	authBody := map[string]interface{}{
		"email":    "user@example.com",
		"password": "password",
	}
	body, err := json.Marshal(authBody)
	if err != nil {
		t.Error(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(middleware.Auth))
	defer ts.Close()
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Error(err)
	}
	if string(respBody) != "test" {
		t.Errorf("expected 'test', got %v", respBody)
	}
}
