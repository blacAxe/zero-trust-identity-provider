package handlers

import (
	"net/http"

	"github.com/omar/zero-trust-idp/db"
)

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from header
	refreshToken := r.Header.Get("X-Refresh-Token")
	if refreshToken == "" {
		http.Error(w, "Missing refresh token", http.StatusBadRequest)
		return
	}

	// Hash it 
	hashed := HashToken(refreshToken)

	// Check DB for valid session
	userID, err := db.GetSession(hashed)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Issue new access token
	newAccessToken, err := GenerateAccessToken(userID, "admin")
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Return new access token
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{
		"access_token": "` + newAccessToken + `"
	}`))
}
