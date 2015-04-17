package jwt

import "testing"

func TestNewJWTMiddleware(t *testing.T) {
	config := &Config{
		Secret: "password",
	}
	middleware, err := NewMiddleware(config)
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
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
