package mgoauth

import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

const (
	databaseName           = "auth_users"
	usersCollection        = "users"
	loginRequestCollection = "request"
)

var (
	sessionPool *mgo.Session
)

func init() {
	var err error
	if sessionPool, err = mgo.Dial("localhost"); err != nil {
		panic(err)
	}

	storage := newStorage()
	if err = storage.CreateIndexes(); err != nil {
		panic(err)
	}

	if err = storage.ClearTemporaryData(); err != nil {
		panic(err)
	}
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

func (self *Storage) CreateIndexes() error {
	userIndex := mgo.Index{
		Key:      []string{"name"},
		Unique:   true,
		DropDups: true,
	}
	if err := self.session.DB(databaseName).C(usersCollection).EnsureIndex(userIndex); err != nil {
		return err
	}

	loginRequestIndex := mgo.Index{
		Key:      []string{"name", "remote_addr"},
		Unique:   true,
		DropDups: true,
	}
	if err := self.session.DB(databaseName).C(loginRequestCollection).EnsureIndex(loginRequestIndex); err != nil {
		return err
	}

	return nil
}

func (self *Storage) ClearTemporaryData() error {
	return self.ClearRequests()
}

func (self *Storage) UserId(name, password string) (string, error) {
	users := self.session.DB(databaseName).C(usersCollection)
	user := User{}
	if err := users.Find(bson.M{"name": name, "password": crypt(password)}).One(&user); err != nil {
		return "", err
	}

	return user.Id.Hex(), nil
}

func (self *Storage) UserById(id string) (User, error) {
	users := self.session.DB(databaseName).C(usersCollection)
	user := User{}

	if err := users.FindId(bson.ObjectIdHex(id)).One(&user); err != nil {
		return User{}, err
	}

	return user, nil
}

func (self *Storage) AddUser(user *User) error {
	if err := self.session.DB(databaseName).C(usersCollection).Insert(user); err != nil {
		return err
	}

	return nil
}

func (self *Storage) AddRequest(name, remoteAddr string) error {
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)

	// try to find login request first
	request := LoginRequest{}
	if err := requestCollection.Find(bson.M{"name": name, "remote_addr": remoteAddr}).One(&request); err == nil {
		// request exists
		request.LastRequest = time.Now().Unix()

		if request.Count > 3 {
			request.Count = 1
		} else {
			request.Count = request.Count + 1
		}

		if err := requestCollection.Update(bson.M{"name": name, "remote_addr": remoteAddr}, request); err != nil {
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

func (self *Storage) RemoveRequest(name, remoteAddr string) error {
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)

	return requestCollection.Remove(bson.M{"name": name, "remote_addr": remoteAddr})
}

func (self *Storage) ClearRequests() error {
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)
	_, err := requestCollection.RemoveAll(bson.M{})
	return err
}

func (self *Storage) IsAllowedRequest(name, remoteAddr string) bool {
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)
	request := LoginRequest{}
	if err := requestCollection.Find(bson.M{"name": name, "remote_addr": remoteAddr}).One(&request); err == nil {
		if request.Count >= 3 {
			timeDelta := time.Now().Unix() - request.LastRequest
			return timeDelta >= 60
		}
	}

	return true
}

func (self *Storage) ResetCounter(name, remoteAddr string) {
	//todo
}
