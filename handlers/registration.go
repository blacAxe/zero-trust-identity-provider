package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/omar/zero-trust-idp/db"
)

// In-memory store for session data
var sessionDataStore = make(map[string]*webauthn.SessionData)

func BeginRegistration(w http.ResponseWriter, r *http.Request, wa *webauthn.WebAuthn) {
	query := r.URL.Query()
	username := query.Get("username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	// Find or Create User
	user, err := db.GetUser(username)
	if err != nil {
		user = db.CreateUser(username)
	}

	// Generate Registration Options
	options, sessionData, err := wa.BeginRegistration(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data to verify against in the Finish step
	sessionDataStore[username] = sessionData

	// Send options to frontend
	w.Header().Set("Content-Type", "application/json")
	JSONResponse(w, options)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request, wa *webauthn.WebAuthn) {
	username := r.URL.Query().Get("username")

	// Get the stored session data
	sessionData, exists := sessionDataStore[username]
	if !exists {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	user, _ := db.GetUser(username)

	// Parse the credential response from the browser
	credential, err := wa.FinishRegistration(user, *sessionData, r)
	if err != nil {
		http.Error(w, "Failed to verify: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Save the Public Key to the user's account
	user.AddCredential(*credential)
	db.SaveUser(user)

	w.Write([]byte("Registration Successful! Passkey saved."))
}

func JSONResponse(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}
