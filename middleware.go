package mgoauth

import (
	"net/http"
)

func CheckAuth(next http.Handler, role int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := false
		if role == EmptyRole {
			authorized = true
		} else {
			cookie, err := r.Cookie("SessionID")
			if err == nil && cookie.Value == "signin" {
				authorized = true
			}
		}

		if authorized {
			next.ServeHTTP(w, r)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	})
}
