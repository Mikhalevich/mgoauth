package mgoauth

import (
	"github.com/gorilla/context"
	"log"
	"net/http"
)

func setCurrentUser(request *http.Request, user User) {
	context.Set(request, "MgoAuthCurrentUser", user)
}

func CurrentUser(request *http.Request) (User, bool) {
	storedUser, ok := context.GetOk(request, "MgoAuthCurrentUser")
	user := User{}
	if !ok {
		// empty user
		return user, false
	}

	user, ok = storedUser.(User)

	if !ok {
		log.Println("Stored context value is not a user")
		return user, false
	}

	return user, true
}
