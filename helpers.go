package mgoauth

import (
	"github.com/gorilla/context"
	"log"
	"net/http"
	"net/smtp"
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

func sendRegistrationMail(emailTo string, validationCode string) error {
	auth := smtp.PlainAuth("", EmailFrom, EmailPassword, EmailHost)
	msg := "From: " + EmailFrom + "\r\n" +
		"To: " + emailTo + "\r\n" +
		"Subject: Registration mail" + "\r\n\r\n" +
		validationCode + "\r\n"
	return smtp.SendMail(EmailHost+":"+EmailPort, auth, EmailFrom, []string{emailTo}, []byte(msg))
}
