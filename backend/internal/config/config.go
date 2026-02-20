package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application.
type Config struct {
	// Database configuration
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	// Server configuration
	ServerPort string

	// JWT configuration
	JWTSecret string

	// Migration configuration
	MigrationPath string
}

var AppConfig *Config

// LoadConfig loads environment variables from .env file and populates Config.
// It should be called early in main() before any other initialization.
func LoadConfig() (*Config, error) {
	// Load .env file (ignore error if file doesn't exist - useful for production)
	if err := godotenv.Load(); err != nil {
		log.Println("[Config] No .env file found, using environment variables")
	}

	config := &Config{
		DBHost:        getEnv("DB_HOST", "127.0.0.1"),
		DBPort:        getEnv("DB_PORT", "5432"),
		DBUser:        getEnv("DB_USER", "postgres"),
		DBPassword:    getEnv("DB_PASSWORD", "postgres"),
		DBName:        getEnv("DB_NAME", "appdb"),
		ServerPort:    getEnv("SERVER_PORT", "8080"),
		JWTSecret:     getEnv("JWT_SECRET", ""),
		MigrationPath: getEnv("MIGRATION_PATH", "./migrations"),
	}

	// Validate required environment variables
	if config.JWTSecret == "" {
		log.Println("[Config] WARNING: JWT_SECRET not set, using default (not secure for production!)")
		config.JWTSecret = "opsflow-dev-secret-change-in-production"
	}

	AppConfig = config
	return config, nil
}

// getEnv gets an environment variable or returns a default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetDatabaseDSN returns the PostgreSQL connection string.
func (c *Config) GetDatabaseDSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.DBHost, c.DBPort, c.DBUser, c.DBPassword, c.DBName)
}

// GetMigrationDSN returns the PostgreSQL connection string for migrations.
func (c *Config) GetMigrationDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName)
}
