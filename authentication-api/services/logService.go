package services

import (
	"context"
	"sort"
	"time"

	"github.com/erneap/authentication/authentication-api/models/config"
	"github.com/erneap/authentication/authentication-api/models/logs"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Crud Functions for Creating, Retrieving, updating and deleting authentication
// log database records

// CRUD Create Function
func CreateLogEntry(dt time.Time, app string, lvl logs.DebugLevel, msg string) error {
	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	entry := &logs.LogEntry{
		DateTime:    dt,
		Application: app,
		Level:       lvl,
		Message:     msg,
	}

	_, err := logCol.InsertOne(context.TODO(), entry)
	return err
}

// CRUD Retrieve Functions - one, between dates for application, by application,
// and all records.
func GetLogEntry(id string) (*logs.LogEntry, error) {
	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	logid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"_id": logid,
	}

	var entry logs.LogEntry
	if err = logCol.FindOne(context.TODO(), filter).Decode(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func GetLogEntriesByApplication(app string) ([]logs.LogEntry, error) {
	var entries []logs.LogEntry

	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	filter := bson.M{
		"application": app,
	}

	cursor, err := logCol.Find(context.TODO(), filter)
	if err != nil {
		return entries, err
	}

	if err = cursor.All(context.TODO(), &entries); err != nil {
		return entries, err
	}

	sort.Sort(logs.ByLogEntry(entries))
	return entries, nil
}

func GetLogEntriesByApplicationAndDates(app string, begin, end time.Time) ([]logs.LogEntry, error) {
	var entries []logs.LogEntry

	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	filter := bson.M{
		"application": app,
		"datetime":    bson.M{"$gte": begin, "$lt": end},
	}

	cursor, err := logCol.Find(context.TODO(), filter)
	if err != nil {
		return entries, err
	}

	if err = cursor.All(context.TODO(), &entries); err != nil {
		return entries, err
	}

	sort.Sort(logs.ByLogEntry(entries))
	return entries, nil
}

func GetLogEntries(app string, begin, end time.Time) ([]logs.LogEntry, error) {
	var entries []logs.LogEntry

	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	filter := bson.M{}

	cursor, err := logCol.Find(context.TODO(), filter)
	if err != nil {
		return entries, err
	}

	if err = cursor.All(context.TODO(), &entries); err != nil {
		return entries, err
	}

	sort.Sort(logs.ByLogEntry(entries))
	return entries, nil
}

// CRUD Update
func UpdateLogEntry(entry logs.LogEntry) error {
	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	filter := bson.M{
		"_id": entry.ID,
	}

	_, err := logCol.ReplaceOne(context.TODO(), filter, entry)
	return err
}

// CRUD Delete functions - delete one by id, delete before date, delete by
// application before date
func DeleteLogEntry(id string) error {
	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	logid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{
		"_id": logid,
	}

	_, err = logCol.DeleteOne(context.TODO(), filter)
	return err
}

func DeleteLogEntriesBeforeDate(dt time.Time) error {
	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	filter := bson.M{
		"datetime": bson.M{"lt": dt},
	}

	_, err := logCol.DeleteMany(context.TODO(), filter)
	return err
}

func DeleteLogEntriesByApplicationBeforeDate(app string, dt time.Time) error {
	logCol := config.GetCollection(config.DB, "authenticate", "logs")

	filter := bson.M{
		"application": app,
		"datetime":    bson.M{"lt": dt},
	}

	_, err := logCol.DeleteMany(context.TODO(), filter)
	return err
}
