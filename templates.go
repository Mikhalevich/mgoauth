package mgoauth

import (
	"html/template"
	"path"
	"runtime"
)

func templateAbsPath(templateName string) string {
	_, filename, _, _ := runtime.Caller(0)
	return path.Join(path.Dir(filename), "templates", templateName)
}

var (
	Templates = template.Must(template.New("Auth").ParseFiles(
		templateAbsPath("Login.html"),
		templateAbsPath("Test.html"),
		templateAbsPath("Register.html"),
		templateAbsPath("EmailValidation.html")))
)

type TemplateUserInfo struct {
	Username string
	Password string
	Email    string
}

type TemplateEmailValidation struct {
	Name string
	Link string
}
