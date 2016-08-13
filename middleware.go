package mgoauth

import (
	"net/http"
)

func CheckAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := false
		cookie, err := r.Cookie("SessionID")
		if err == nil && cookie.Value == "signin" {
			authorized = true
		}

		if !authorized && r.URL.Path != "/login" {
			http.Redirect(w, r, "/login", http.StatusFound)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
