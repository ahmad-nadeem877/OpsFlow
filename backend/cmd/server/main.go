package main

import (
	"fmt"
	"log"
	"net/http"
	"opsflow/internal/config"
	"opsflow/internal/helpers"
	users "opsflow/internal/users"

	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	// Load configuration from .env file (must be first)
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	r := setupRoutes()
	runMigration(cfg)

	if err := helpers.ConnectToDatabase(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	helpers.Ping()

	serverAddr := fmt.Sprintf(":%s", cfg.ServerPort)
	if err := r.Run(serverAddr); err != nil {
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
	users.SetupAuthRoutes(r.Group("/auth"))

	return r
}

func runMigration(cfg *config.Config) {
	migrationSource := fmt.Sprintf("file://%s", cfg.MigrationPath)
	m, err := migrate.New(migrationSource, cfg.GetMigrationDSN())
	if err != nil {
		log.Fatal(err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatal(err)
	}
}
