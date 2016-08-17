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
	authTemplate = template.Must(template.New("Auth").ParseFiles(
		templateAbsPath("Login.html"),
		templateAbsPath("Test.html"),
		templateAbsPath("Register.html")))
)

type UserInfo struct {
	Username string
	Password string
}

func setUserCookie(w http.ResponseWriter) {
	expire := time.Now().Add(5 * time.Minute)
	cookie := http.Cookie{Name: "SessionID", Value: "signin", Expires: expire, HttpOnly: true}
	http.SetCookie(w, &cookie)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var userInfo UserInfo

	if r.Method == "POST" {
		userInfo.Username = r.FormValue("name")
		userInfo.Password = r.FormValue("password")

		storage := newStorage()
		defer storage.close()

		if storage.isValidUser(userInfo.Username, userInfo.Password) {
			setUserCookie(w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	if err := authTemplate.ExecuteTemplate(w, "Login.html", userInfo); err != nil {
		panic(err)
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	var userInfo UserInfo

	if r.Method == "POST" {
		userInfo.Username = r.FormValue("name")
		userInfo.Password = r.FormValue("password")

		storage := newStorage()
		defer storage.close()

		if err := storage.addUser(userInfo.Username, userInfo.Password, UserRole); err == nil {
			setUserCookie(w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	if err := authTemplate.ExecuteTemplate(w, "Register.html", userInfo); err != nil {
		panic(err)
	}
}

func Test(w http.ResponseWriter, r *http.Request) {
	if err := authTemplate.ExecuteTemplate(w, "Test.html", nil); err != nil {
		panic(err)
	}
}

func AdminTest(w http.ResponseWriter, r *http.Request) {
	if err := authTemplate.ExecuteTemplate(w, "Test.html", nil); err != nil {
		panic(err)
	}
}
