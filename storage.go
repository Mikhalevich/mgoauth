package mgoauth

import (
	"crypto/sha1"
	"fmt"
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

	createIndexes(sessionPool)
}

func createIndexes(session *mgo.Session) {
	index := mgo.Index{
		Key:      []string{"name"},
		Unique:   true,
		DropDups: true,
	}
	if err := session.DB(databaseName).C(usersCollection).EnsureIndex(index); err != nil {
		panic(err)
	}
}

func crypt(password string) [sha1.Size]byte {
	return sha1.Sum([]byte(password))
}

type Storage struct {
	session *mgo.Session
}

func newStorage() *Storage {
	storage := &Storage{
		session: sessionPool.Copy(),
	}

	return storage
}

func (self *Storage) close() {
	self.session.Close()
}

func (self *Storage) userId(name string, password string) string {
	users := self.session.DB(databaseName).C(usersCollection)
	user := User{}
	if err := users.Find(bson.M{"name": name, "password": crypt(password)}).One(&user); err != nil {
		return ""
	}

	return user.Id.Hex()
}

func (self *Storage) userById(id string) (User, error) {
	users := self.session.DB(databaseName).C(usersCollection)
	user := User{}

	if err := users.FindId(bson.ObjectIdHex(id)).One(&user); err != nil {
		return User{}, err
	}

	return user, nil
}

func (self *Storage) addUser(name string, password string, role int) (string, error) {
	user := &User{
		Id:       bson.NewObjectId(),
		Name:     name,
		Password: crypt(password),
		Role:     role,
	}

	if err := self.session.DB(databaseName).C(usersCollection).Insert(user); err != nil {
		fmt.Println(err)
		return "", err
	}

	return user.Id.Hex(), nil
}
