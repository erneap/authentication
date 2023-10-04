package services

import (
	"github.com/erneap/go-models/logs"
	"github.com/erneap/go-models/svcs"
	"github.com/gin-gonic/gin"
)

func AddLogEntry(c *gin.Context, portion, category, title, msg string) error {
	empID := svcs.GetRequestor(c)
	emp, _ := GetEmployee(empID)
	return svcs.AddLogEntry2(portion, category, title, msg, emp)
}

func GetLogEntries(c *gin.Context, portion string, year int) ([]logs.LogEntry2, error) {
	empID := svcs.GetRequestor(c)
	emp, _ := GetEmployee(empID)
	return svcs.GetLogEntries2(portion, year, emp)
}
