package handlers

import (
	"net/http"

	"github.com/omar/zero-trust-idp/db"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	// Get refresh token
	refreshToken := r.Header.Get("X-Refresh-Token")
	if refreshToken == "" {
		http.Error(w, "Missing refresh token", http.StatusBadRequest)
		return
	}

	// Hash it
	hashed := HashToken(refreshToken)

	// Delete session from DB
	err := db.DeleteSession(hashed)
	if err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	// Respond
	w.Write([]byte("Logged out successfully"))
}