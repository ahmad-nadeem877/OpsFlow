package helpers

import (
	"fmt"
	"log"
	"opsflow/internal/models"
	"runtime/debug"

	"github.com/jmoiron/sqlx"
)

var DB *sqlx.DB

type DatabaseInfo struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DbName   string `json:"dbname"`
}

var DbInfo DatabaseInfo

func ConnectToDatabase(host, port, user, password, dbname string) error {
	DbInfo.Host = host
	DbInfo.Port = port
	DbInfo.User = user
	DbInfo.Password = password
	DbInfo.DbName = dbname

	return connectDb()
}

func connectDb() error {

	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", DbInfo.Host, DbInfo.Port, DbInfo.User, DbInfo.Password, DbInfo.DbName)
	var err error
	DB, err = sqlx.Open("postgres", dbinfo)

	return err
}

// Ping - test function to validate connectivity to the database
func Ping() error {
	err := DB.Ping()
	if err != nil {
		fmt.Printf("[Ping] MySQl Connection Ping Failed Err:%s\n", err)
		return err
	}
	// if no error. Ping is successful
	fmt.Println("[Ping] Ping to database successful, connection is still alive")

	return nil
}

// CloseDB - used when we're shutting down the application to properly dispose Off the pointer
func CloseDB() {
	DB.Close()
}

// UserByEmail is used for login to fetch id, email, and password_hash.
type UserByEmail struct {
	Id           string `db:"id"`
	Email        string `db:"email"`
	PasswordHash string `db:"password_hash"`
}

// GetUserByEmail returns a user by email for login verification.
func GetUserByEmail(email string) (UserByEmail, error) {
	var u UserByEmail
	err := DB.Get(&u, "SELECT id, email, password_hash FROM users WHERE email = $1", email)
	if err != nil {
		return UserByEmail{}, err
	}
	return u, nil
}

func CreateAccount(user models.User) (models.User, error) {
	query := "INSERT INTO users (email, password_hash, email_verified, is_active) VALUES (:email, :password, :email_verified, :is_active) returning id, email, created_at, email_verified, is_active"

	rows, err := DB.NamedQuery(query, &user)
	if err != nil {
		log.Printf("[CreateAccount] Failed to Execute Generic DB Query, Err:%s\n", err)
		return models.User{}, err
	}
	var newUser models.User
	for rows.Next() {
		err = rows.StructScan(&newUser)
		if err != nil {
			log.Printf("[CreateAccount] Failed to Execute Struct Scan, Err:%s\n", err)
			return models.User{}, err
		}
	}
	return newUser, nil
}

// InsertAccount - Generic Function to perform upsert operation
func InsertUpdateTable(tblName string, givenFields string, fieldsNvalues map[string]interface{}, valuesCSV, updatesCSV, constraint string) error {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[InsertAccount] Panic! Recovered", string(debug.Stack()), r)
		}
	}()
	query := "INSERT INTO " + tblName + "(" + givenFields + ") VALUES (" + valuesCSV + ") ON CONFLICT ON CONSTRAINT " + constraint + " DO UPDATE SET " + updatesCSV
	rows, err := DB.Queryx(query)
	if err != nil {
		log.Printf("[InsertAccount] Failed to Execute Generic DB Query, Err:%s\n", err)
		return err
	}
	defer rows.Close()

	return nil
}

// InsertUpdateTable - Generic Function to insert an account LOCKED for accounts table ONLY
func InsertUpdateReturnTable(tblName string, givenFields string, valuesCSV, updatesCSV, constraint string) (map[string]interface{}, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[InsertUpdateReturnTable] Panic! Recovered", string(debug.Stack()), r)
		}
	}()
	query := "INSERT INTO " + tblName + "(" + givenFields + ") VALUES (" + valuesCSV + ") ON CONFLICT ON CONSTRAINT " + constraint + " DO UPDATE SET " + updatesCSV + " RETURNING *"
	fmt.Printf("QUERY: %v\n", query)
	results := make(map[string]interface{})

	rows, err := DB.Queryx(query)
	if err != nil {
		log.Printf("[InsertUpdateReturnTable] Failed to Execute Generic DB Query, Err:%s\n", err)
		return results, err
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.MapScan(results)
	}

	return results, err
}
