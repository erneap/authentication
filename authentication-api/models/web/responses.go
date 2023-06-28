package web

import (
	"time"

	"github.com/erneap/authentication/authentication-api/models/users"
)

type AuthenticationResponse struct {
	Token       string         `json:"token"`
	UserID      string         `json:"userid,omitempty"`
	Name        users.UserName `json:"name"`
	Permissions []string       `json:"permissions,omitempty"`
	PwdExpires  time.Time      `json:"pwdExpires,omitempty"`
	Exception   string         `json:"exception"`
}

type UserResponse struct {
	User      users.User `json:"user"`
	Exception string     `json:"exception"`
}

type TokenRenewalResponse struct {
	Token     string `json:"token"`
	Exception string `json:"exception"`
}

type UsersResponse struct {
	Users     []users.User `json:"users"`
	Exception string       `json:"exception"`
}

type ExceptionResponse struct {
	Exception string `json:"exception"`
}
