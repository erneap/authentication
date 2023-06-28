package main

import (
	"fmt"

	"github.com/erneap/authentication/authentication-api/controllers"
	"github.com/erneap/go-models/config"
	"github.com/erneap/go-models/services"
	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("Starting")

	// run database
	config.ConnectDB()

	// add routes
	router := gin.Default()
	adminRoles := []string{"metrics-admin", "scheduler-scheduler",
		"scheduler-siteleader", "scheduler-teamleader", "scheduler-admin"}
	api := router.Group("/authentication/api/v1")
	{
		authenticate := api.Group("/authenticate")
		{
			authenticate.POST("/", controllers.Login)
			authenticate.PUT("/", services.CheckJWT(), controllers.RenewToken)
			authenticate.DELETE("/:userid", services.CheckJWT(), controllers.Logout)
		}
		user := api.Group("/user")
		{
			user.GET("/:userid", services.CheckRoleList(adminRoles),
				controllers.GetUser)
			user.POST("/", services.CheckRoleList(adminRoles), controllers.AddUser)
			user.PUT("/", services.CheckRoleList(adminRoles), controllers.UpdateUser)
			user.DELETE("/:userid", services.CheckRoleList(adminRoles),
				controllers.DeleteUser)
		}
		api.GET("/users", services.CheckRoleList(adminRoles), controllers.GetUsers)
	}

	// listen on port 6000
	router.Run(":6000")
}
