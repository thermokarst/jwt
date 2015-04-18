package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

var authFunc = func(email, password string) (bool, error) {
	return true, nil
}

var claimsFunc = func(id string) (map[string]interface{}, error) {
	currentTime := time.Now()
	return map[string]interface{}{
		"iat": currentTime.Unix(),
		"exp": currentTime.Add(time.Minute * 60 * 24).Unix(),
	}, nil
}

func newJWTMiddlewareOrFatal(t *testing.T) *JWTMiddleware {
	config := &Config{
		Secret: "password",
		Auth:   authFunc,
		Claims: claimsFunc,
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
		t.Errorf("wanted password, got %v", middleware.secret)
	}
	authVal, err := middleware.auth("", "")
	if err != nil {
		t.Fatal(err)
	}
	if authVal != true {
		t.Errorf("wanted true, got %v", authVal)
	}
	claimsVal, err := middleware.claims("1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := claimsVal["iat"]; !ok {
		t.Errorf("wanted a claims set, got %v", claimsVal)
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
		t.Errorf("wanted test, got %v", resp.Body.String())
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

	j := strings.Split(string(respBody), ".")

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
}
