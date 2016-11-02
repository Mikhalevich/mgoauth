package mgoauth

import (
	"log"
	"net/http"
	"time"
)

func CheckAuth(next http.Handler, role int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := false
		defer func() {
			if authorized {
				next.ServeHTTP(w, r)
			} else {
				http.Redirect(w, r, UrlLoginPage, http.StatusFound)
			}
		}()

		pagePriority, ok := RolePriority[role]
		if !ok {
			log.Println("Invalid handler role")
			return
		}

		if role == EmptyRole {
			authorized = true
			return
		}

		cookie, err := r.Cookie(SessionIdName)
		if err != nil {
			return
		}

		sessionId := cookie.Value
		storage := NewStorage()
		defer storage.Close()

		user, err := storage.UserBySessionId(sessionId)
		if err != nil {
			log.Println("No such session")
			return
		}

		userPriority, ok := RolePriority[user.Role]
		if !ok {
			log.Println("Invalid user role")
			return
		}

		if userPriority < pagePriority {
			log.Println("Not allower for current user")
			return
		}

		if user.SessionExpires < time.Now().Unix() {
			log.Println("Session was expired")
			return
		}

		authorized = true
		setCurrentUser(r, user)
	})
}
