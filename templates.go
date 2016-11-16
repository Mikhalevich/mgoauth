package mgoauth

import (
	"fmt"
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

type TemplateBase struct {
	Errors map[string]string
}

func (self *TemplateBase) AddError(name string, errorValue string, params ...interface{}) {
	self.Errors[name] = fmt.Sprintf(errorValue, params...)
}

type TemplateUserInfo struct {
	TemplateBase
	Username string
	Password string
	Email    string
}

func NewTemplateUserInfo() *TemplateUserInfo {
	var info TemplateUserInfo
	info.Errors = make(map[string]string)
	return &info
}

type TemplateEmailValidation struct {
	TemplateBase
	Name string
	Link string
}
