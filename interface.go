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
	Id             bson.ObjectId   `bson:"_id,omitempty"`
	Name           string          `bson:"name"`
	Password       [sha1.Size]byte `bson:"password"`
	Role           int             `bson:"role"`
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
