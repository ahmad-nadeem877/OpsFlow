package helpers

import (
	"fmt"

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
