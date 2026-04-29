package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/omar/zero-trust-idp/db"
)

func BeginLogin(w http.ResponseWriter, r *http.Request, wa *webauthn.WebAuthn) {
	username := r.URL.Query().Get("username")
	user, err := db.GetUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// For Login, use wa.BeginLogin instead of BeginRegistration
	options, sessionData, err := wa.BeginLogin(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionDataStore[username] = sessionData
	JSONResponse(w, options)
}

func FinishLogin(w http.ResponseWriter, r *http.Request, wa *webauthn.WebAuthn) {
	username := r.URL.Query().Get("username")

	// Get the user from DB package
	user, err := db.GetUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Get the session data stored in LoginBegin
	sessionData, ok := sessionDataStore[username]
	if !ok {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	// IMPORTANT: Actually verify the WebAuthn response from the browser
	// This checks if the hardware signature is valid
	_, err = wa.FinishLogin(user, *sessionData, r)
	if err != nil {
		http.Error(w, "Failed to verify passkey: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Determine the role
	role := "user"
	if user.WebAuthnName() == "bob" || user.Name == "bob" {
		role = "user"
	}

	// Generate the token with the role
	token, err := GenerateJWT(user.Name, role)
	if err != nil {
		http.Error(w, "Failed to generate token", 500)
		return
	}

	// Clean up the session so it can't be reused (Replay Attack protection)
	delete(sessionDataStore, username)

	// Send the token back
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "success", "token": "` + token + `"}`))

	f, err := os.Create("token.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	fmt.Fprint(f, strings.TrimSpace(token))
	f.Close()
}
