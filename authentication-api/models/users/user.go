package users

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID              primitive.ObjectID `json:"id" bson:"_id"`
	EmailAddress    string             `json:"emailAddress" bson:"emailAddress"`
	Password        string             `json:"password" bson:"password"`
	PasswordExpires time.Time          `json:"passwordExpires" bson:"passwordExpires"`
	BadAttempts     uint               `json:"badAttempts" bson:"badAttempts"`
	FirstName       string             `json:"firstName" bson:"firstName"`
	MiddleName      string             `json:"middleName,omitempty" bson:"middleName,omitempty"`
	LastName        string             `json:"lastName" bson:"lastName"`
	Workgroups      []string           `json:"workgroups" bson:"workgroups"`
}

type ByUser []User

func (c ByUser) Len() int { return len(c) }
func (c ByUser) Less(i, j int) bool {
	if c[i].LastName == c[j].LastName {
		if c[i].FirstName == c[j].LastName {
			return c[i].MiddleName < c[j].MiddleName
		}
		return c[i].FirstName < c[j].FirstName
	}
	return c[i].LastName < c[j].LastName
}
func (c ByUser) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

func (u *User) IsInGroup(app, group string) bool {
	answer := false
	for _, perm := range u.Workgroups {
		parts := strings.Split(perm, "-")
		if strings.EqualFold(app, parts[0]) && strings.EqualFold(group, parts[1]) {
			answer = true
		}
	}
	return answer
}

func (u *User) SetPassword(passwd string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(passwd), 12)
	if err != nil {
		return err
	}
	u.Password = string(hashed)
	u.BadAttempts = 0
	u.PasswordExpires = time.Now().UTC().AddDate(0, 0, 90)
	return nil
}

func (u *User) Authenticate(passwd string) error {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(passwd))
	if err != nil {
		u.BadAttempts++
		return err
	}

	if u.PasswordExpires.Before(time.Now().UTC()) {
		u.BadAttempts++
		return errors.New("password expired")
	}
	if u.BadAttempts > 2 {
		return errors.New("account locked")
	}

	u.BadAttempts = 0
	return nil
}

func (u *User) GetFullName() string {
	if u.MiddleName != "" {
		return fmt.Sprintf("%s %s. %s", u.FirstName, u.MiddleName[:1], u.LastName)
	}
	return fmt.Sprintf("%s %s", u.FirstName, u.LastName)
}

func (u *User) GetLastFirst() string {
	if u.MiddleName != "" {
		return fmt.Sprintf("%s, %s %s.", u.LastName, u.FirstName, u.MiddleName[:1])
	}
	return fmt.Sprintf("%s, %s", u.LastName, u.FirstName)
}
