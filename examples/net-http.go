package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/thermokarst/jwt"
)

func protectMe(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "secured")
}

func main() {
	var authFunc = func(email string, password string) error {
		// Hard-code a user
		if email != "test" || password != "test" {
			return errors.New("invalid credentials")
		}
		return nil
	}

	var claimsFunc = func(string) (map[string]interface{}, error) {
		currentTime := time.Now()
		return map[string]interface{}{
			"iat": currentTime.Unix(),
			"exp": currentTime.Add(time.Minute * 60 * 24).Unix(),
		}, nil
	}

	var verifyClaimsFunc = func([]byte) error {
		// We don't really care about the claims, just approve as-is
		return nil
	}

	config := &jwt.Config{
		Secret: "password",
		Auth:   authFunc,
		Claims: claimsFunc,
	}
	j, err := jwt.NewMiddleware(config)
	if err != nil {
		panic(err)
	}
	protect := http.HandlerFunc(protectMe)
	http.Handle("/authenticate", j.GenerateToken())
	http.Handle("/secure", j.Secure(protect, verifyClaimsFunc))
	http.ListenAndServe(":8080", nil)
}
