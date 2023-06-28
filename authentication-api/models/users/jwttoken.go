package users

import (
	"github.com/golang-jwt/jwt"
)

type JWTClaim struct {
	UserID       string `json:"userid"`
	EmailAddress string `json:"emailAddress"`
	jwt.StandardClaims
}

type UserName struct {
	FirstName  string `json:"firstName"`
	MiddleName string `json:"middleName,omitempty"`
	LastName   string `json:"lastName"`
}
