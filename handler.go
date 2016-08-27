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

type TemplateUserInfo struct {
	Username string
	Password string
}

func setUserCookie(w http.ResponseWriter, sessionId string) {
	expire := time.Now().Add(5 * time.Minute)
	cookie := http.Cookie{Name: "SessionID", Value: sessionId, Expires: expire, HttpOnly: true}
	http.SetCookie(w, &cookie)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var userInfo TemplateUserInfo

	if r.Method == "POST" {
		userInfo.Username = r.FormValue("name")
		userInfo.Password = r.FormValue("password")

		storage := newStorage()
		defer storage.close()

		if storage.isValidRequest(userInfo.Username, r.RemoteAddr) {
			userId := storage.userId(userInfo.Username, userInfo.Password)
			if len(userId) > 0 {
				storage.removeRequest(userInfo.Username, r.RemoteAddr)
				setUserCookie(w, userId)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			} else {
				storage.addRequest(userInfo.Username, r.RemoteAddr)
			}
		}
	}

	if err := authTemplate.ExecuteTemplate(w, "Login.html", userInfo); err != nil {
		panic(err)
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	var userInfo TemplateUserInfo

	if r.Method == "POST" {
		userInfo.Username = r.FormValue("name")
		userInfo.Password = r.FormValue("password")

		storage := newStorage()
		defer storage.close()

		if userId, err := storage.addUser(userInfo.Username, userInfo.Password, UserRole); err == nil {
			setUserCookie(w, userId)
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
