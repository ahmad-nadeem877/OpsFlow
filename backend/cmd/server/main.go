package main

import (
	"log"
	"net/http"
	"opsflow/internal/helpers"
	users "opsflow/internal/users"

	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {

	r := setupRoutes()
	runMigration()

	if err := helpers.ConnectToDatabase("127.0.0.1", "5432", "postgres", "postgres", "appdb"); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	helpers.Ping()

	if err := r.Run(":8080"); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}

}

func setupRoutes() *gin.Engine {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		// Return JSON response
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	users.SetupUserRoutes(r.Group("/users"))

	return r
}

func runMigration() {
	m, err := migrate.New(
		"file://./migrations",
		"postgres://postgres:postgres@localhost:5432/appdb?sslmode=disable",
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatal(err)
	}
}
