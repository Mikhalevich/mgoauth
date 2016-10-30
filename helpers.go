package mgoauth

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"github.com/gorilla/context"
	"html"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
)

const (
	randomIdLenght  = 10
	randomIdSymbols = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
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

func sendRegistrationMail(name string, emailTo string, validationCode string) error {
	var body bytes.Buffer
	link := fmt.Sprintf("%s?email=%s&code=%s", UrlEmailValidationPage, html.EscapeString(emailTo), html.EscapeString(validationCode))
	templateParams := &TemplateEmailValidation{
		Name: name,
		Link: link,
	}
	if err := Templates.ExecuteTemplate(&body, "EmailValidation.html", templateParams); err != nil {
		return err
	}

	auth := smtp.PlainAuth("", EmailFrom, EmailPassword, EmailHost)
	msg := "From: " + EmailFrom + "\r\n" +
		"To: " + emailTo + "\r\n" +
		"MIME-Version: 1.0" + "\r\n" +
		"Content-type: text/html" + "\r\n" +
		"Subject: Registration mail" + "\r\n\r\n" +
		body.String() + "\r\n"
	return smtp.SendMail(EmailHost+":"+EmailPort, auth, EmailFrom, []string{emailTo}, []byte(msg))
}

func generateRandomId() string {
	bytes := make([]byte, randomIdLenght)
	rand.Read(bytes)

	for index, value := range bytes {
		bytes[index] = randomIdSymbols[value%byte(len(randomIdSymbols))]
	}

	return string(bytes)
}

func crypt(password string) [sha1.Size]byte {
	return sha1.Sum([]byte(password))
}
