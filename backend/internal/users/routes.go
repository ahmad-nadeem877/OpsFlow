package users

import (
	"log"
	"net/http"
	"opsflow/internal/helpers"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func SetupUserRoutes(rg *gin.RouterGroup) {
	{
		rg.GET("/health", Health)
		rg.POST("/signup", Signup)
		rg.POST("/login", Login)
		rg.POST("/logout", Logout)
	}
}

// SetupAuthRoutes registers authenticated routes (e.g. /auth/me).
func SetupAuthRoutes(rg *gin.RouterGroup) {
	rg.GET("/me", AuthMiddleware(), CurrentUser)
}

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString, err := ctx.Cookie(jwtCookieName)
		if err != nil || tokenString == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid token"})
			return
		}

		claims := &jwtClaims{}
		parsedToken, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (interface{}, error) {
			return []byte(GetJWTSecret()), nil
		})
		if err != nil || !parsedToken.Valid {
			log.Println("[AuthMiddleware] invalid token:", err)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		user, err := helpers.GetUserByID(claims.UserID)
		if err != nil {
			log.Println("[AuthMiddleware] user not found:", err)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		ctx.Set(string(ContextKey), &user)
		ctx.Next()
	}
}
