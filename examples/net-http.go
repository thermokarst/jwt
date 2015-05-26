package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/thermokarst/jwt"
)

func protectMe(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "secured")
}

func dontProtectMe(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "not secured")
}

func auth(email string, password string) error {
	// Hard-code a user
	if email != "test" || password != "test" {
		return errors.New("invalid credentials")
	}
	return nil
}

func setClaims(id string) (map[string]interface{}, error) {
	currentTime := time.Now()
	return map[string]interface{}{
		"iat": currentTime.Unix(),
		"exp": currentTime.Add(time.Minute * 60 * 24).Unix(),
	}, nil
}

func verifyClaims(claims []byte, r *http.Request) error {
	currentTime := time.Now()
	var c struct {
		Iat int64
		Exp int64
	}
	_ = json.Unmarshal(claims, &c)
	if currentTime.After(time.Unix(c.Exp, 0)) {
		return errors.New("this token has expired")
	}
	return nil
}

func main() {
	config := &jwt.Config{
		Secret: "password",
		Auth:   auth,
		Claims: setClaims,
	}

	j, err := jwt.New(config)
	if err != nil {
		panic(err)
	}

	protect := http.HandlerFunc(protectMe)
	dontProtect := http.HandlerFunc(dontProtectMe)

	http.Handle("/authenticate", j.GenerateToken())
	http.Handle("/secure", j.Secure(protect, verifyClaims))
	http.Handle("/insecure", dontProtect)
	http.ListenAndServe(":8080", nil)
}
