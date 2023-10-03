package services

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/erneap/go-models/svcs"
	"github.com/gin-gonic/gin"
)

func AddLogEntry(c *gin.Context, portion, category, title, msg string) error {
	empID := svcs.GetRequestor(c)
	name := ""
	site := "General"
	emp, err := GetEmployee(empID)
	if err == nil {
		name = emp.Name.GetLastFirst()
		site = emp.SiteID
	}
	logBase := os.Getenv("LOG_DIR")
	chgDate := time.Now()
	logLevel, _ := strconv.Atoi(os.Getenv("LOGLEVEL"))

	if logLevel < 1 || !strings.EqualFold(category, "debug") {
		logPath := path.Join(logBase, site, portion)
		if err := os.MkdirAll(logPath, 0755); err != nil {
			return err
		}

		logPath = path.Join(logPath, fmt.Sprintf("%s-%d.log", portion, chgDate.Year()))

		entry := chgDate.UTC().Format("060102T150405Z") + "\t(" +
			strings.ToUpper(category) + ") " + strings.ToUpper(title) + "\t" +
			msg
		if name != "" {
			entry += fmt.Sprintf("(%s)", name)
		}
		entry += "\n"

		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString(entry); err != nil {
			return err
		}
	}
	return nil
}

func GetLogEntries(c *gin.Context, portion string, year int) ([]string, error) {
	empID := svcs.GetRequestor(c)
	site := "General"
	emp, err := GetEmployee(empID)
	if err == nil {
		site = emp.SiteID
	}
	logBase := os.Getenv("LOG_DIR")
	if strings.TrimSpace(site) == "" {
		site = "General"
	}

	logPath := path.Join(logBase, site, portion)
	if err := os.MkdirAll(logPath, 0755); err != nil {
		return nil, err
	}

	logPath = path.Join(logPath, fmt.Sprintf("%s-%d.log", portion, year))

	if _, err := os.Stat(logPath); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s does not exist", logPath)
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	return lines, nil
}
