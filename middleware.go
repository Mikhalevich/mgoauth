package mgoauth

import (
	"log"
	"net/http"
	"time"
)

func CheckAuth(next http.Handler, role int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := false
		pagePriority, ok := RolePriority[role]
		if !ok {
			log.Println("Invalid handler role")
		} else if role == EmptyRole {
			authorized = true
		} else {
			if cookie, err := r.Cookie(SessionIdName); err == nil {
				sessionId := cookie.Value
				storage := NewStorage()
				defer storage.Close()

				if user, err := storage.UserBySessionId(sessionId); err == nil {
					userPriority, ok := RolePriority[user.Role]
					if !ok {
						log.Println("Invalid user role")
					} else if userPriority < pagePriority {
						log.Println("Not allower for current user")
					} else {
						if user.SessionExpires < time.Now().Unix() {
							log.Println("Session was expired")
						} else {
							authorized = true
							setCurrentUser(r, user)
						}
					}
				}
			}
		}

		if authorized {
			next.ServeHTTP(w, r)
		} else {
			http.Redirect(w, r, UrlLoginPage, http.StatusFound)
		}
	})
}
