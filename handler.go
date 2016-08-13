package mgoauth

import (
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

func auth(username, password string, w http.ResponseWriter) bool {
	storage := newStorage()
	defer storage.close()

	if storage.isValidUser(username, password) {
		expire := time.Now().Add(5 * time.Minute)
		cookie := http.Cookie{Name: "SessionID", Value: "signin", Expires: expire, HttpOnly: true}
		http.SetCookie(w, &cookie)
		return true
	}

	return false
}

func Login(w http.ResponseWriter, r *http.Request) {
	var username string
	var password string

	if r.Method == "POST" {
		username = r.FormValue("name")
		password = r.FormValue("password")

		if auth(username, password, w) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	if err := authTemplate.ExecuteTemplate(w, "Login.html", nil); err != nil {
		panic(err)
	}
}

func Test(w http.ResponseWriter, r *http.Request) {
	if err := authTemplate.ExecuteTemplate(w, "Test.html", nil); err != nil {
		panic(err)
	}
}
