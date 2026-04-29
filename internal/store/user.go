package store

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// User represents Zero Trust user model
type User struct {
	ID          []byte
	Username    string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user's unique ID
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's username
func (u *User) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName returns the user's display name
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials returns the list of registered public keys
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// In-memory DB 
var UserDB = make(map[string]*User)

func CreateUser(username string) *User {
	user := &User{
		ID:          []byte(uuid.New().String()),
		Username:    username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}
	UserDB[username] = user
	return user
}
