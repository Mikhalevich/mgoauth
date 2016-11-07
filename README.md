# web authentication on golang using mongodb
## example
```

package main

import (
	"github.com/Mikhalevich/mgoauth"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strings"
)

type Route struct {
	Name        string
	Pattern     string
	Methods     string
	Role        int
	HandlerFunc http.HandlerFunc
}

type Routes []Route

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		router.
			Methods(strings.Split(route.Methods, ",")...).
			Name(route.Name).
			Path(route.Pattern).
			Handler(mgoauth.CheckAuth(route.HandlerFunc, route.Role))
	}

	return router
}

var routes = Routes{
	Route{
		"Index",
		"/",
		"GET",
		mgoauth.UserRole,
		mgoauth.Test,
	},
	Route{
		"AdminIndex",
		"/admin",
		"GET",
		mgoauth.AdminRole,
		mgoauth.AdminTest,
	},
	Route{
		"Login",
		"/login",
		"GET,POST",
		mgoauth.EmptyRole,
		mgoauth.Login,
	},
	Route{
		"Register",
		"/register",
		"GET,POST",
		mgoauth.EmptyRole,
		mgoauth.Register,
	},
	Route{
		"Validation",
		"/validation",
		"GET",
		mgoauth.EmptyRole,
		mgoauth.EmailValidation,
	},
}

func main() {
	router := NewRouter()
	log.Fatal(http.ListenAndServe(":8080", router))
}


```
