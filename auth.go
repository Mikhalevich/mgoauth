package mgoauth

import (
	//"gopkg.in/mgo.v2"
	//"gopkg.in/mgo.v2/bson"
	"html/template"
	"net/http"
	"path"
	"runtime"
	"time"
)

func templateAbsPath(templateName string) string {
	_, filename, _, _ := runtime.Caller(0)
	return path.Join(path.Dir(filename), "templates", templateName)
}

var (
	authTemplate = template.Must(template.New("Auth").ParseFiles(templateAbsPath("Login.html"), templateAbsPath("Test.html")))
)

func Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if err := authTemplate.ExecuteTemplate(w, "Login.html", nil); err != nil {
			panic(err)
		}

	case "POST":
		Auth(w, r)
	}
}

func Auth(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("name")
	password := r.FormValue("password")

	if username == "guest" && password == "guest123" {
		expire := time.Now().Add(5 * time.Minute)
		cookie := http.Cookie{Name: "SessionID", Value: "signin", Expires: expire, HttpOnly: true}
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	}
}

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

func Test(w http.ResponseWriter, r *http.Request) {
	if err := authTemplate.ExecuteTemplate(w, "Test.html", nil); err != nil {
		panic(err)
	}
}
