package mgoauth

import (
	"crypto/sha1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

const (
	databaseName           = "users"
	usersCollection        = "users"
	loginRequestCollection = "login_request"

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

type LoginRequest struct {
	Id          bson.ObjectId `bson:"_id,omitempty"`
	UserName    string        `bson:"name"`
	RemoteAddr  string        `bson:"remote_addr"`
	LastRequest int64         `bson:"last_request"`
	Count       int           `bson:"count"`
}

func init() {
	var err error
	if sessionPool, err = mgo.Dial("localhost"); err != nil {
		panic(err)
	}

	createIndexes(sessionPool)
}

func createIndexes(session *mgo.Session) {
	userIndex := mgo.Index{
		Key:      []string{"name"},
		Unique:   true,
		DropDups: true,
	}
	if err := session.DB(databaseName).C(usersCollection).EnsureIndex(userIndex); err != nil {
		panic(err)
	}

	loginRequestIndex := mgo.Index{
		Key:      []string{"name", "remote_addr"},
		Unique:   true,
		DropDups: true,
	}
	if err := session.DB(databaseName).C(loginRequestCollection).EnsureIndex(loginRequestIndex); err != nil {
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
		return "", err
	}

	return user.Id.Hex(), nil
}

func (self *Storage) addLoginRequest(name, remoteAddr string) error {
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)

	// try to find login request first
	request := LoginRequest{}
	if err := requestCollection.Find(bson.M{"name": name, "remote_addr": remoteAddr}).One(&request); err != nil {
		// request exists
		request.LastRequest = time.Now().Unix()
		request.Count = request.Count + 1

		if err := requestCollection.Update(request, bson.M{"name": name, "remote_addr": remoteAddr}); err != nil {
			return err
		}
	} else {
		// new reqeust
		request.UserName = name
		request.RemoteAddr = remoteAddr
		request.LastRequest = time.Now().Unix()
		request.Count = 1
		if err := requestCollection.Insert(request); err != nil {
			return err
		}
	}

	return nil
}

func (self *Storage) removeLoginRequest(name, remoteAddr string) error {
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)

	return requestCollection.Remove(bson.M{"name": name, "remote_addr": remoteAddr})
}
