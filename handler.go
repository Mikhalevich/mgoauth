package mgoauth

import (
	"log"
	"net/http"
	"time"
)

func setUserCookie(w http.ResponseWriter, sessionId string) {
	expire := time.Now().Add(SessionExpirePeriod * time.Second)
	cookie := http.Cookie{Name: SessionIdName, Value: sessionId, Expires: expire, HttpOnly: true}
	http.SetCookie(w, &cookie)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var userInfo TemplateUserInfo
	renderTemplate := true

	defer func() {
		if renderTemplate {
			if err := Templates.ExecuteTemplate(w, "Login.html", userInfo); err != nil {
				log.Println(err)
			}
		}
	}()

	if r.Method == "POST" {
		userInfo.Username = r.FormValue("name")
		userInfo.Password = r.FormValue("password")

		storage := NewStorage()
		defer storage.Close()

		if !storage.IsAllowedRequest(userInfo.Username, r.RemoteAddr) {
			log.Println("Request is not allowed")
			return
		}

		user, err := storage.UserByNameAndPassword(userInfo.Username, crypt(userInfo.Password))
		if err != nil {
			log.Println("Invalid username or password", err)
			storage.AddRequest(userInfo.Username, r.RemoteAddr)
			return
		}

		err = storage.RemoveRequest(userInfo.Username, r.RemoteAddr)
		if err != nil {
			log.Println("Unable to remove request", err)
			// continue programm execution
		}

		if UseEmailValidation && len(user.ActivationCode) > 0 {
			log.Println("Email not validated")
			renderTemplate = false
			http.Redirect(w, r, UrlRegisterPage, http.StatusFound)
			return
		}

		sessionId := generateRandomId(32)
		currentTime := time.Now().Unix()
		err = storage.UpdateLoginInfo(user.Id, currentTime, sessionId, currentTime+SessionExpirePeriod)
		if err != nil {
			log.Println("Unable to update last login info", err)
		} else {
			renderTemplate = false
			setUserCookie(w, sessionId)
			http.Redirect(w, r, UrlRootPage, http.StatusFound)
			return
		}
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	var userInfo TemplateUserInfo
	renderTemplate := true

	defer func() {
		if renderTemplate {
			if err := Templates.ExecuteTemplate(w, "Register.html", userInfo); err != nil {
				log.Println(err)
			}
		}
	}()

	if r.Method == "POST" {
		userInfo.Username = r.FormValue("name")
		userInfo.Password = r.FormValue("password")
		userInfo.Email = r.FormValue("email")

		storage := NewStorage()
		defer storage.Close()

		activationCode := ""
		sessionId := ""
		var sessionExpires int64 = 0
		var loginTime int64 = 0
		if UseEmailValidation {
			activationCode = generateRandomId(10)
		} else {
			sessionId = generateRandomId(32)
			sessionExpires = time.Now().Unix() + SessionExpirePeriod
			loginTime = time.Now().Unix()
		}

		user := &User{
			Name:           userInfo.Username,
			Email:          userInfo.Email,
			Password:       crypt(userInfo.Password),
			Role:           UserRole,
			Registered:     time.Now().Unix(),
			LastLogin:      loginTime,
			ActivationCode: activationCode,
			SessionId:      sessionId,
			SessionExpires: sessionExpires,
		}

		err := storage.AddUser(user)
		if err != nil {
			log.Println("Unable to add user: ", err)
			return
		}

		if UseEmailValidation {
			err = sendRegistrationMail(userInfo.Username, userInfo.Email, activationCode)
			if err != nil {
				log.Println(err)
			} else {
				renderTemplate = false
				// todo: redirect to notification about sending mail page
				http.Redirect(w, r, UrlRootPage, http.StatusFound)
			}
			return
		} else {
			renderTemplate = false
			setUserCookie(w, sessionId)
			http.Redirect(w, r, UrlRootPage, http.StatusFound)
			return
		}
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
		log.Println(err)
	}
}

func AdminTest(w http.ResponseWriter, r *http.Request) {
	if err := Templates.ExecuteTemplate(w, "Test.html", nil); err != nil {
		log.Println(err)
	}
}
