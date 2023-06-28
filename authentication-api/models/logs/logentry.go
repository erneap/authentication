package logs

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type DebugLevel int64

const (
	Minimal DebugLevel = iota
	Information
	Debug
	Full
)

type LogEntry struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	DateTime    time.Time          `json:"datetime" bson:"datetime"`
	Application string             `json:"application" bson:"application"`
	Level       DebugLevel         `json:"debuglevel" bson:"debuglevel"`
	Message     string             `json:"message" bson:"message"`
}

type ByLogEntry []LogEntry

func (c ByLogEntry) Len() int { return len(c) }
func (c ByLogEntry) Less(i, j int) bool {
	return c[i].DateTime.After(c[j].DateTime)
}
func (c ByLogEntry) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
