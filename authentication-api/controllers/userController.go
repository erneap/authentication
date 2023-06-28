package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/erneap/go-models/logs"
	"github.com/erneap/go-models/services"
	"github.com/erneap/go-models/users"
	"github.com/erneap/go-models/web"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"honnef.co/go/tools/config"
)

func Login(c *gin.Context) {
	var data web.AuthenticationRequest
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))

	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest,
			web.AuthenticationResponse{Name: users.UserName{},
				Token: "", Exception: "Trouble with request"})
		return
	}

	user, err := services.GetUserByEMail(data.EmailAddress)
	if err != nil {
		msg := "GetUserByEmail Problem: " + err.Error()
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusNotFound,
			web.AuthenticationResponse{Name: users.UserName{}, Token: "",
				Exception: msg})
		return
	}

	if err := user.Authenticate(data.Password); err != nil {
		err := services.UpdateUser(*user)
		if err != nil {
			c.JSON(http.StatusNotFound,
				web.AuthenticationResponse{Name: users.UserName{},
					Token: "", Exception: "Problem Updating Database"})
			return
		}
		c.JSON(http.StatusUnauthorized,
			web.AuthenticationResponse{Name: users.UserName{},
				Token: "", Exception: err.Error()})
		return
	}
	err = services.UpdateUser(*user)
	if err != nil {
		c.JSON(http.StatusNotFound,
			web.AuthenticationResponse{Name: users.UserName{},
				Token: "", Exception: "Problem Updating Database"})
		return
	}

	// create token
	tokenstring, err := services.CreateToken(user.ID, user.EmailAddress)
	if err != nil {
		msg := "CreateToken Problem: " + err.Error()
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusNotFound,
			web.AuthenticationResponse{Name: users.UserName{}, Token: "",
				Exception: msg})
		return
	}

	msg := fmt.Sprintf("User Login: %s logged into %s at %s", user.GetLastFirst(),
		data.Application, time.Now().Format("01/02/06 15:04"))
	if loglevel >= int(logs.Minimal) {
		services.CreateLogEntry(time.Now().UTC(), "authentication",
			logs.Minimal, msg)
	}

	c.JSON(http.StatusOK, web.AuthenticationResponse{
		Token:  tokenstring,
		UserID: user.ID.Hex(),
		Name: users.UserName{
			FirstName:  user.FirstName,
			MiddleName: user.MiddleName,
			LastName:   user.LastName,
		},
		Permissions: user.Workgroups,
		Exception:   "",
	})
}

func RenewToken(c *gin.Context) {
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))
	tokenString := c.GetHeader("Authorization")
	claims, err := services.ValidateToken(tokenString)
	if err != nil {
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, err.Error())
		}
	}

	// replace token by passing a new token in the response header
	id, _ := primitive.ObjectIDFromHex(claims.UserID)
	tokenString, _ = services.CreateToken(id, claims.EmailAddress)

	c.JSON(http.StatusOK, web.AuthenticationResponse{
		Token:     tokenString,
		UserID:    claims.UserID,
		Name:      users.UserName{},
		Exception: "",
	})
}

func Logout(c *gin.Context) {
	id := c.Param("userid")
	app := c.Param("applicaiton")
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))

	user, err := services.GetUserByID(id)
	if err != nil {
		msg := "GetUserByEmail Problem: " + err.Error()
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusNotFound, web.ExceptionResponse{Exception: err.Error()})
		return
	}

	msg := fmt.Sprintf("User Login: %s logged into %s at %s", user.GetLastFirst(),
		app, time.Now().Format("01/02/06 15:04"))
	if loglevel >= int(logs.Minimal) {
		services.CreateLogEntry(time.Now().UTC(), "authentication",
			logs.Minimal, msg)
	}
	c.Status(http.StatusOK)
}

func UpdateUser(c *gin.Context) {
	var data web.UpdateRequest
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))

	if err := c.ShouldBindJSON(&data); err != nil {
		if loglevel >= int(logs.Debug) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, "Problem Binding JSON Object to UpdateUser")
		}
		c.JSON(http.StatusBadRequest,
			web.UserResponse{User: users.User{}, Exception: "Trouble with request"})
		return
	}

	user, err := services.GetUserByID(data.UserID)
	if err != nil {
		msg := "GetUserByID Problem: " + err.Error()
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusNotFound, web.ExceptionResponse{Exception: msg})
		return
	}

	switch strings.ToLower(data.Field) {
	case "password":
		user.SetPassword(data.Value)
	case "first", "firstname":
		user.FirstName = data.Value
	case "middle", "middlename":
		user.MiddleName = data.Value
	case "last", "lastname":
		user.LastName = data.Value
	case "email", "emailaddress":
		user.EmailAddress = data.Value
	case "unlock":
		user.BadAttempts = 0
	case "addperm", "addworkgroup", "addpermission":
		found := false
		for _, perm := range user.Workgroups {
			if strings.EqualFold(perm, data.Value) {
				found = true
			}
		}
		if !found {
			user.Workgroups = append(user.Workgroups, strings.ToLower(data.Value))
		}
	case "removeworkgroup", "remove", "removeperm", "removepermission":
		pos := -1
		for i, perm := range user.Workgroups {
			if strings.EqualFold(perm, data.Value) {
				pos = i
			}
		}
		if pos >= 0 {
			user.Workgroups = append(user.Workgroups[:pos],
				user.Workgroups[pos+1:]...)
		}
	}

	err = services.UpdateUser(*user)
	if err != nil {
		msg := "UpdateUser Problem: " + err.Error()
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusBadRequest, web.ExceptionResponse{Exception: msg})
		return
	}

	c.JSON(http.StatusOK, web.UserResponse{User: *user, Exception: ""})
}

func AddUser(c *gin.Context) {
	var data web.AddUserRequest
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))

	if err := c.ShouldBindJSON(&data); err != nil {
		if loglevel >= int(logs.Debug) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, "Problem Binding JSON Object to AddUser")
		}
		c.JSON(http.StatusBadRequest,
			web.UserResponse{User: users.User{}, Exception: "Trouble with request"})
		return
	}

	user := services.CreateUser(data.EmailAddress, data.FirstName,
		data.MiddleName, data.LastName, data.Password)
	switch strings.ToLower(data.Application) {
	case "metrics":
		user.Workgroups = append(user.Workgroups, "metrics-geoint")
	case "scheduler":
		user.Workgroups = append(user.Workgroups, "scheduler-employee")
	default:
		user.Workgroups = append(user.Workgroups, "default-employee")
	}
	err := services.UpdateUser(*user)
	if err != nil {
		if loglevel >= int(logs.Debug) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, "Problem Binding JSON Object to AddUser")
		}
		c.JSON(http.StatusBadRequest,
			web.UserResponse{User: users.User{}, Exception: "Trouble with request"})
		return
	}
	c.JSON(http.StatusOK, web.UserResponse{User: *user, Exception: ""})
}

func DeleteUser(c *gin.Context) {
	id := c.Param("userid")
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))

	err := services.DeleteUser(id)
	if err != nil {
		msg := "DeleteUser Problem: " + err.Error()
		if loglevel >= int(logs.Debug) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusBadRequest, web.ExceptionResponse{Exception: msg})
		return
	}
	c.Status(http.StatusOK)
}

func GetUser(c *gin.Context) {
	id := c.Param("userid")
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))

	user, err := services.GetUserByID(id)
	if err != nil {
		msg := "GetUser Problem: " + err.Error()
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusBadRequest, web.ExceptionResponse{Exception: msg})
		return
	}
	c.JSON(http.StatusOK, web.UserResponse{User: *user, Exception: ""})
}

func GetUsers(c *gin.Context) {
	loglevel, _ := strconv.Atoi(config.Config("LOGLEVEL"))

	users, err := services.GetUsers()
	if err != nil {
		msg := "GetUsers Problem: " + err.Error()
		if loglevel >= int(logs.Minimal) {
			services.CreateLogEntry(time.Now().UTC(), "authentication",
				logs.Minimal, msg)
		}
		c.JSON(http.StatusBadRequest, web.ExceptionResponse{Exception: msg})
		return
	}
	c.JSON(http.StatusOK, web.UsersResponse{Users: users, Exception: ""})
}
