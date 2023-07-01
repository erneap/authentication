package main

import (
	"fmt"

	"github.com/erneap/authentication/controllers"
	"github.com/erneap/go-models/config"
	"github.com/erneap/go-models/svcs"
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
	api := router.Group("/authentication/api/v2")
	{
		authenticate := api.Group("/authenticate")
		{
			authenticate.POST("/", controllers.Login)
			authenticate.PUT("/", svcs.CheckJWT(), controllers.RenewToken)
			authenticate.DELETE("/:userid", svcs.CheckJWT(), controllers.Logout)
		}
		user := api.Group("/user")
		{
			user.GET("/:userid", svcs.CheckRoleList(adminRoles),
				controllers.GetUser)
			user.POST("/", svcs.CheckRoleList(adminRoles), controllers.AddUser)
			user.PUT("/", svcs.CheckRoleList(adminRoles), controllers.UpdateUser)
			user.DELETE("/:userid", svcs.CheckRoleList(adminRoles),
				controllers.DeleteUser)
		}
		reset := api.Group("/reset")
		{
			reset.POST("/", controllers.StartPasswordReset)
			reset.PUT("/", controllers.PasswordReset)
		}
		api.GET("/users", svcs.CheckRoleList(adminRoles), controllers.GetUsers)
	}

	// listen on port 6000
	router.Run(":6000")
}
