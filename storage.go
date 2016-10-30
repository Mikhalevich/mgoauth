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

	storage := NewStorage()
	if err = storage.createIndexes(); err != nil {
		panic(err)
	}

	if err = storage.clearTemporaryData(); err != nil {
		panic(err)
	}
}

type Storage struct {
	session *mgo.Session
}

func NewStorage() *Storage {
	storage := &Storage{
		session: sessionPool.Copy(),
	}

	return storage
}

func (self *Storage) Close() {
	self.session.Close()
}

func (self *Storage) createIndexes() error {
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

func (self *Storage) clearTemporaryData() error {
	return self.ClearRequests()
}

func (self *Storage) UserByNameAndPassword(name, password string) (User, error) {
	usersCollection := self.session.DB(databaseName).C(usersCollection)
	user := User{}

	cryptedPassword := crypt(password)
	query := usersCollection.Find(bson.M{"name": name, "password": cryptedPassword})
	rows, err := query.Count()
	if err != nil {
		return User{}, err
	}

	if rows <= 0 {
		query = usersCollection.Find(bson.M{"email": name, "password": cryptedPassword})
	}

	err = query.One(&user)
	if err != nil {
		return User{}, err
	}

	return user, nil
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

func (self *Storage) AddLoginTime(id string, loginTime int64) error {
	users := self.session.DB(databaseName).C(usersCollection)

	return users.UpdateId(bson.ObjectIdHex(id), bson.M{"$set": bson.M{"last_login": loginTime}})
}

func (self *Storage) ResetActivationCode(email string, code string) bool {
	users := self.session.DB(databaseName).C(usersCollection)

	query := users.Find(bson.M{"email": email, "activation_code": code})
	rows, err := query.Count()
	if err != nil {
		return false
	}

	if rows <= 0 {
		return false
	}

	err = users.Update(bson.M{"email": email, "activation_code": code}, bson.M{"$set": bson.M{"activation_code": ""}})
	if err != nil {
		return false
	}

	return true
}

func (self *Storage) AddRequest(name, remoteAddr string) error {
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)

	// try to find login request first
	request := LoginRequest{}
	if err := requestCollection.Find(bson.M{"name": name, "remote_addr": remoteAddr}).One(&request); err == nil {
		// request exists
		request.LastRequest = time.Now().Unix()
		request.Count = request.Count + 1

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
		if request.Count >= LoginRequestMaxCount {
			timeDelta := time.Now().Unix() - request.LastRequest
			allowed := timeDelta >= LoginRequestWaitingPeriod

			if allowed {
				self.resetCounter(request)
			}
			return allowed
		}
	}

	return true
}

func (self *Storage) resetCounter(request LoginRequest) error {
	request.Count = 1
	requestCollection := self.session.DB(databaseName).C(loginRequestCollection)
	return requestCollection.Update(bson.M{"name": request.UserName, "remote_addr": request.RemoteAddr}, request)
}
