package services

import (
	"context"

	"github.com/erneap/authentication/authentication-api/models/config"
	"github.com/erneap/authentication/authentication-api/models/users"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Crud Functions for Creating, Retrieving, updating and deleting user database
// records

// CRUD Create Function - New User

func CreateUser(email, first, middle, last, password string) *users.User {
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	filter := bson.M{
		"emailAddress": email,
	}

	var user users.User
	if err := userCol.FindOne(context.TODO(), filter).Decode(&user); err != nil {
		user = users.User{
			ID:           primitive.NewObjectID(),
			EmailAddress: email,
			FirstName:    first,
			MiddleName:   middle,
			LastName:     last,
		}
		user.SetPassword(password)
		userCol.InsertOne(context.TODO(), user)
	} else {
		user.EmailAddress = email
		user.FirstName = first
		user.MiddleName = middle
		user.LastName = last
		user.SetPassword(password)

		userCol.ReplaceOne(context.TODO(), filter, user)
	}
	return &user
}

// Retrieve Functions for getting a user or users based on need.
func GetUserByID(id string) (*users.User, error) {
	userCol := config.GetCollection(config.DB, "authenticate", "users")
	userid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"_id": userid,
	}

	var user users.User
	err = userCol.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByEMail(email string) (*users.User, error) {
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	filter := bson.M{
		"emailAddress": email,
	}

	var user users.User
	err := userCol.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUsers() ([]users.User, error) {
	var users []users.User

	userCol := config.GetCollection(config.DB, "authenticate", "users")

	cursor, err := userCol.Find(context.TODO(), bson.M{})
	if err != nil {
		return users, err
	}

	if err = cursor.All(context.TODO(), &users); err != nil {
		return users, err
	}
	return users, nil
}

// CRUD Update Function
func UpdateUser(user users.User) error {
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	filter := bson.M{
		"_id": user.ID,
	}

	_, err := userCol.ReplaceOne(context.TODO(), filter, user)
	return err
}

// CRUD Delete Function
func DeleteUser(id string) error {
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	userid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{
		"_id": userid,
	}

	_, err = userCol.DeleteOne(context.TODO(), filter)
	return err
}
