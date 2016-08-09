package mgoauth

import (
	"gopkg.in/mgo.v2"
	//"gopkg.in/mgo.v2/bson"
)

var (
	sessionPool *mgo.Session
)

func init() {
	var err error
	if sessionPool, err = mgo.Dial("localhost"); err != nil {
		panic(err)
	}
}

type Storage struct {
	session *mgo.Session
}

func (self *Storage) close() {
	self.session.Close()
}

func (self *Storage) isValidUser(name string, password string) bool {
	if name == "guest" && password == "guest123" {
		return true
	} else {
		return false
	}
}

func newStorage() *Storage {
	storage := &Storage{
		session: sessionPool.Copy(),
	}

	return storage
}
