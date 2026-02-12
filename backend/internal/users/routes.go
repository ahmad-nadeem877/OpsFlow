package users

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetupUserRoutes(rg *gin.RouterGroup) {
	{
		rg.GET("/health", Health)
	}
}

func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "route working",
	})
}
