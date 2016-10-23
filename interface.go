package mgoauth

import (
	"crypto/sha1"
	"gopkg.in/mgo.v2/bson"
)

// common

const (
	UrlRootPage  = "/"
	UrlLoginPage = "/login"
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

type User struct {
	Id             bson.ObjectId   `bson:"_id,omitempty"`
	Name           string          `bson:"name"`
	Email          string          `bson:"email"`
	Password       [sha1.Size]byte `bson:"password"`
	Role           int             `bson:"role"`
	Registered     int64           `bson:"registered"`
	LastLogin      int64           `bson:"last_login"`
	ActivationCode string          `bson:"activation_code"`
}

type UserStorage interface {
	UserId(name, passwd string) (string, error)
	UserById(id string) (User, error)
	AddUser(user User) error
}

// request storage

const (
	LoginRequestMaxCount      = 3
	LoginRequestWaitingPeriod = 60 // sec
)

type LoginRequest struct {
	Id          bson.ObjectId `bson:"_id,omitempty"`
	UserName    string        `bson:"name"`
	RemoteAddr  string        `bson:"remote_addr"`
	LastRequest int64         `bson:"last_request"`
	Count       int           `bson:"count"`
}

type LoginRequestStorage interface {
	AddRequest(name, remoteAddr string) error
	RemoveRequest(name, remoteAddr string) error
	ClearRequests() error
	IsAllowedRequest(name, remoteAddr string) bool
}

// user handlers

const (
	SessionIdName       = "SessionID"
	SessionExpirePeriod = 5 * 60 // sec
)
