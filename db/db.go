package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/go-webauthn/webauthn/webauthn"
)

var DB *sql.DB

// Initialize DB connection
func InitDB() error {
	connStr := os.Getenv("DB_URL")
	if connStr == "" {
		return fmt.Errorf("DB_URL not set")
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	if err = db.Ping(); err != nil {
		return err
	}

	DB = db
	return nil
}

type User struct {
	ID          string
	Name        string
	Credentials []webauthn.Credential
}

// WebAuthn interface methods
func (u *User) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (u *User) WebAuthnIcon() string                       { return "" }

func GetUser(username string) (*User, error) {
	query := `SELECT id, username, credentials FROM users WHERE username=$1`

	var id string
	var credsJSON []byte

	err := DB.QueryRow(query, username).Scan(&id, &username, &credsJSON)
	if err != nil {
		return nil, err
	}

	var creds []webauthn.Credential
	json.Unmarshal(credsJSON, &creds)

	return &User{
		ID:          id,
		Name:        username,
		Credentials: creds,
	}, nil
}

func CreateUser(username string) (*User, error) {
	id := fmt.Sprintf("%d", time.Now().UnixNano())

	query := `INSERT INTO users (id, username, credentials, created_at)
			  VALUES ($1, $2, $3, $4)`

	emptyCreds, _ := json.Marshal([]webauthn.Credential{})

	_, err := DB.Exec(query, id, username, emptyCreds, time.Now())
	if err != nil {
		return nil, err
	}

	return &User{
		ID:          id,
		Name:        username,
		Credentials: []webauthn.Credential{},
	}, nil
}

func SaveUser(u *User) error {
	credsJSON, _ := json.Marshal(u.Credentials)

	query := `UPDATE users SET credentials=$1 WHERE username=$2`
	_, err := DB.Exec(query, credsJSON, u.Name)
	return err
}

func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

func CreateSession(userID string, hashedToken string, expiry time.Time) error {
	id := fmt.Sprintf("%d", time.Now().UnixNano())

	query := `INSERT INTO sessions (id, user_id, refresh_token, expires_at, created_at)
	          VALUES ($1, $2, $3, $4, $5)`

	_, err := DB.Exec(query, id, userID, hashedToken, expiry, time.Now())
	return err
}

func GetSession(hashedToken string) (string, error) {
	query := `SELECT user_id FROM sessions WHERE refresh_token=$1 AND expires_at > NOW()`

	var userID string
	err := DB.QueryRow(query, hashedToken).Scan(&userID)
	return userID, err
}

func DeleteSession(hashedToken string) error {
	query := `DELETE FROM sessions WHERE refresh_token=$1`
	_, err := DB.Exec(query, hashedToken)
	return err
}