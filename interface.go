package mgoauth

import (
	"crypto/sha1"
	"gopkg.in/mgo.v2/bson"
)

// connection

type Connectioner interface {
	CreateIndexes() error
	ClearTemporaryData() error
	Close()
}

// user storage

const (
	EmptyRole = iota
	UserRole
	AdminRole
)

type User struct {
	Id       bson.ObjectId   `bson:"_id,omitempty"`
	Name     string          `bson:"name"`
	Password [sha1.Size]byte `bson:"password"`
	Role     int             `bson:"role"`
}

type UserStorage interface {
	UserId(name, passwd string) (string, error)
	UserById(id string) (User, error)
	AddUser(user User) error
}

// request storage

const (
	MaxRequestCount = 3
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
	ResetCounter(name, remoteAddr string) error
}