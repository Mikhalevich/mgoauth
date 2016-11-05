package mgoauth

import (
	"crypto/sha1"
	"errors"
	"gopkg.in/mgo.v2/bson"
)

// common

const (
	UrlBase                = "http://localhost:8080"
	UrlRootPage            = "/"
	UrlLoginPage           = "/login"
	UrlRegisterPage        = "/register"
	UrlEmailValidationPage = UrlBase + "/validation"

	UseEmailValidation = true
	EmailFrom          = "noreplymgoauth@gmail.com"
	EmailPassword      = "mgoauth123"
	EmailHost          = "smtp.gmail.com"
	EmailPort          = "587"
)

// connection

type Connectioner interface {
	Close()
}

// user storage

const (
	EmptyRole = iota
	UserRole
	AdminRole
)

var (
	RolePriority = map[int]int{
		EmptyRole: 10,
		UserRole:  20,
		AdminRole: 30,
	}
)

type TypeId bson.ObjectId

func NewTypeId() TypeId {
	return TypeId(bson.NewObjectId())
}

func TypeIdFromHex(id string) (TypeId, error) {
	if bson.IsObjectIdHex(id) {
		return TypeId(bson.ObjectIdHex(id)), nil
	} else {
		return "", errors.New("Invalid type id hex string")
	}
}

func (self TypeId) Hex() string {
	return bson.ObjectId(self).Hex()
}

type TypePassword [sha1.Size]byte

type User struct {
	Id             TypeId       `bson:"_id,omitempty"`
	Name           string       `bson:"name"`
	Email          string       `bson:"email"`
	Password       TypePassword `bson:"password"`
	Role           int          `bson:"role"`
	Registered     int64        `bson:"registered"`
	LastLogin      int64        `bson:"last_login"`
	ActivationCode string       `bson:"activation_code"`
	SessionId      string       `bson:"session_id"`
	SessionExpires int64        `bson:"session_expires"`
}

type UserStorage interface {
	UserByNameAndPassword(name string, password TypePassword) (User, error)
	UserById(id TypeId) (User, error)
	UserBySessionId(sessionId string) (User, error)
	AddUser(user User) error
	UpdateLoginInfo(id TypeId, loginTime int64, sessionId string, expires int64) error
	ResetActivationCode(email string, code string) bool
}

// request storage

const (
	LoginRequestMaxCount      = 3
	LoginRequestWaitingPeriod = 60 // sec
)

type LoginRequest struct {
	Id          TypeId `bson:"_id,omitempty"`
	UserName    string `bson:"name"`
	RemoteAddr  string `bson:"remote_addr"`
	LastRequest int64  `bson:"last_request"`
	Count       int    `bson:"count"`
}

type LoginRequestStorage interface {
	AddRequest(name, remoteAddr string) error
	GetRequest(name, remoteAddr string) (LoginRequest, error)
	RemoveRequest(name, remoteAddr string) error
	ClearRequests() error
	ResetRequestCounter(request LoginRequest) error
}

// user handlers

const (
	SessionIdName       = "SessionID"
	SessionExpirePeriod = 5 * 60 // sec
)
