package users

import (
	"log"
	"net/http"
	"opsflow/internal/helpers"
	"opsflow/internal/models"
	"os"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "route working",
	})
}

func Signup(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[SignUp] Panic! Recovered", string(debug.Stack()), r)
		}
	}()
	var newUser models.User
	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, _ := HashPassword(newUser.Password)
	newUser.Password = hashedPassword

	user, err := helpers.CreateAccount(newUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// jsonObj, err := json.Marshal(user)
	c.JSON(http.StatusBadRequest, user)
}

// LoginRequest is the request body for login (email and password).
type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// jwtClaims holds claims for the JWT token.
type jwtClaims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

const (
	jwtCookieName = "token"
	jwtExpiry     = 24 * time.Hour
)

func Login(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[Login] Panic! Recovered", string(debug.Stack()), r)
		}
	}()

	var body LoginRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: email and password required"})
		return
	}

	user, err := helpers.GetUserByEmail(body.Email)
	if err != nil {
		log.Println("[Login]: user not found:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	secret := getJWTSecret()
	claims := jwtClaims{
		UserID: user.Id,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Println("[Login]: failed to sign token:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	c.SetCookie(jwtCookieName, tokenString, int(jwtExpiry.Seconds()), "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}

const ContextKey = "user"

// userResponse is the authenticated user without password hash.
type userResponse struct {
	Id            string    `json:"id"`
	Email         string    `json:"email"`
	CreatedAt     time.Time `json:"created_at"`
	EmailVerified bool      `json:"email_verified"`
	IsActive      bool      `json:"is_active"`
}

func CurrentUser(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[CurrentUser] Panic! Recovered", string(debug.Stack()), r)
		}
	}()

	val, exists := c.Get(string(ContextKey))
	if !exists || val == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	user, ok := val.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user in context"})
		return
	}
	// Return user without password
	c.JSON(http.StatusOK, userResponse{
		Id:            user.Id,
		Email:         user.Email,
		CreatedAt:     user.CreatedAt,
		EmailVerified: user.EmailVerified,
		IsActive:      user.IsActive,
	})
}

func Logout(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[Logout] Panic! Recovered", string(debug.Stack()), r)
		}
	}()

	// Clear the token cookie (same name and path as Login)
	c.SetCookie(jwtCookieName, "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// GetJWTSecret returns the JWT signing secret (used by middleware).
func GetJWTSecret() string {
	return getJWTSecret()
}

func getJWTSecret() string {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return s
	}
	return "opsflow-dev-secret"
}

func HashPassword(password string) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[HashPassword] Panic! Recovered", string(debug.Stack()), r)
		}
	}()

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
