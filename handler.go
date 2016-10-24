package mgoauth

import (
	"crypto/sha1"
	"html/template"
	"log"
	"net/http"
	"path"
	"runtime"
	"time"

	"gopkg.in/mgo.v2/bson"
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
	Email    string
}

func crypt(password string) [sha1.Size]byte {
	return sha1.Sum([]byte(password))
}

func setUserCookie(w http.ResponseWriter, sessionId string) {
	expire := time.Now().Add(SessionExpirePeriod * time.Second)
	cookie := http.Cookie{Name: SessionIdName, Value: sessionId, Expires: expire, HttpOnly: true}
	http.SetCookie(w, &cookie)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var userInfo TemplateUserInfo

	if r.Method == "POST" {
		userInfo.Username = r.FormValue("name")
		userInfo.Password = r.FormValue("password")

		storage := NewStorage()
		defer storage.Close()

		if storage.IsAllowedRequest(userInfo.Username, r.RemoteAddr) {
			if userId, err := storage.UserId(userInfo.Username, userInfo.Password); err != nil {
				storage.AddRequest(userInfo.Username, r.RemoteAddr)
			} else {
				if err := storage.RemoveRequest(userInfo.Username, r.RemoteAddr); err != nil {
					log.Println(err)
				}
				if err := storage.AddLoginTime(userId, time.Now().Unix()); err != nil {
					log.Println(err)
				}
				setUserCookie(w, userId)
				http.Redirect(w, r, UrlRootPage, http.StatusFound)
				return
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
		userInfo.Email = r.FormValue("email")

		storage := NewStorage()
		defer storage.Close()

		user := &User{
			Id:         bson.NewObjectId(),
			Name:       userInfo.Username,
			Email:      userInfo.Email,
			Password:   crypt(userInfo.Password),
			Role:       UserRole,
			Registered: time.Now().Unix(),
			LastLogin:  time.Now().Unix(),
		}
		if err := storage.AddUser(user); err == nil {
			setUserCookie(w, user.Id.Hex())
			http.Redirect(w, r, UrlRootPage, http.StatusFound)
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
