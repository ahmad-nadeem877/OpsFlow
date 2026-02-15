package models

import "time"

type User struct {
	Id            string    `json:"id" db:"id"`
	Email         string    `json:"email" db:"email"`
	Password      string    `json:"password" db:"password"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	EmailVerified bool      `json:"email_verified" db:"email_verified"`
	IsActive      bool      `json:"is_active" db:"is_active"`
}
