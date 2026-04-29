package db

import (
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User model that WebAuthn understands
type User struct {
	ID          []byte
	Name        string
	Credentials []webauthn.Credential
}

// WebAuthn interface methods (required by the library)
func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (u *User) WebAuthnIcon() string                       { return "" }

func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// Simple in-memory storage
var userStore = make(map[string]*User)

func GetUser(name string) (*User, error) {
	user, ok := userStore[name]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func CreateUser(name string) *User {
	user := &User{ID: []byte(name), Name: name}
	userStore[name] = user
	return user
}

func SaveUser(u *User) {
	userStore[u.Name] = u
}
