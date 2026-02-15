package users

import (
	"github.com/gin-gonic/gin"
)

func SetupUserRoutes(rg *gin.RouterGroup) {
	{
		rg.GET("/health", Health)
		rg.POST("/signup", Signup)
		rg.POST("/login", Login)
		rg.POST("/logout", Logout)
	}
}
