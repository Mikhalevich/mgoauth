package mgoauth

import (
	"crypto/sha1"
	"log"
	"net/http"
	"time"

	"gopkg.in/mgo.v2/bson"
)

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

				if len(userId) <= 0 {
					// email not verified
					http.Redirect(w, r, UrlRegisterPage, http.StatusFound)
					return
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

	if err := Templates.ExecuteTemplate(w, "Login.html", userInfo); err != nil {
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

		activationCode := ""
		if UseEmailValidation {
			activationCode = generateRandomId()
		}

		user := &User{
			Id:             bson.NewObjectId(),
			Name:           userInfo.Username,
			Email:          userInfo.Email,
			Password:       crypt(userInfo.Password),
			Role:           UserRole,
			Registered:     time.Now().Unix(),
			LastLogin:      time.Now().Unix(),
			ActivationCode: activationCode,
		}
		if err := storage.AddUser(user); err == nil {
			if UseEmailValidation {
				err = sendRegistrationMail(userInfo.Username, userInfo.Email, activationCode)
				if err != nil {
					log.Println(err)
				} else {
					// todo: redirect to notification about sending mail page
					http.Redirect(w, r, UrlRootPage, http.StatusFound)
					return
				}
			} else {
				setUserCookie(w, user.Id.Hex())
				http.Redirect(w, r, UrlRootPage, http.StatusFound)
				return
			}
		}
	}

	if err := Templates.ExecuteTemplate(w, "Register.html", userInfo); err != nil {
		panic(err)
	}
}

func EmailValidation(w http.ResponseWriter, r *http.Request) {
	if !UseEmailValidation {
		// todo: print error
		return
	}

	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")

	storage := NewStorage()
	defer storage.Close()

	if storage.ResetActivationCode(email, code) {
		http.Redirect(w, r, UrlRootPage, http.StatusFound)
	} else {
		http.Redirect(w, r, UrlRegisterPage, http.StatusFound)
	}
}

func Test(w http.ResponseWriter, r *http.Request) {
	if err := Templates.ExecuteTemplate(w, "Test.html", nil); err != nil {
		panic(err)
	}
}

func AdminTest(w http.ResponseWriter, r *http.Request) {
	if err := Templates.ExecuteTemplate(w, "Test.html", nil); err != nil {
		panic(err)
	}
}
