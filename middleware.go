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
			if cookie, err := r.Cookie(SessionIdName); err == nil {
				userId := cookie.Value

				storage := NewStorage()
				defer storage.Close()

				if user, err := storage.UserById(userId); err == nil {
					if user.Role >= role {
						authorized = true
					}
				}
			}
		}

		if authorized {
			next.ServeHTTP(w, r)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	})
}
