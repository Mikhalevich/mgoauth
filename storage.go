package mgoauth

import (
	"crypto/sha1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	databaseName    = "users"
	usersCollection = "users"

	EmptyRole = iota
	UserRole
	AdminRole
)

var (
	sessionPool *mgo.Session
)

type User struct {
	Id       bson.ObjectId   `bson:"_id,omitempty"`
	Name     string          `bson:"name"`
	Password [sha1.Size]byte `bson:"password"`
	Role     int             `bson:"role"`
}

func init() {
	var err error
	if sessionPool, err = mgo.Dial("localhost"); err != nil {
		panic(err)
	}
}

func crypt(password string) [sha1.Size]byte {
	return sha1.Sum([]byte(password))
}

type Storage struct {
	session *mgo.Session
}

func (self *Storage) close() {
	self.session.Close()
}

func (self *Storage) isValidUser(name string, password string) bool {
	users := self.session.DB(databaseName).C(usersCollection)
	var count int
	count, err := users.Find(bson.M{"name": name, "password": crypt(password)}).Count()

	if err != nil {
		return false
	}

	if count >= 1 {
		return true
	} else {
		return false
	}
}

func (self *Storage) addUser(name string, password string, role int) error {
	user := &User{
		Name:     name,
		Password: crypt(password),
		Role:     role,
	}
	return self.session.DB(databaseName).C(usersCollection).Insert(user)
}

func newStorage() *Storage {
	storage := &Storage{
		session: sessionPool.Copy(),
	}

	return storage
}
