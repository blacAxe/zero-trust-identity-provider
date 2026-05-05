package main

import (
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/omar/zero-trust-idp/db"
	"github.com/omar/zero-trust-idp/handlers"
	"github.com/joho/godotenv"
)

func secretHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Congrats Bob! This is top-secret data only visible with a Passkey."))
}

func main() {

	godotenv.Load()

	// Initialize DB
	err := db.InitDB()
	if err != nil {
		log.Fatal("DB init failed:", err)
	}

	// Configure the WebAuthn instance
	wconfig := &webauthn.Config{
		RPDisplayName: "Zero Trust IDP",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	}

	webAuthnInstance, err := webauthn.New(wconfig)
	if err != nil {
		log.Fatal("Failed to create WebAuthn instance:", err)
	}

	// Create a NEW ServeMux
	mux := http.NewServeMux()

	fileServer := http.FileServer(http.Dir("./static"))

	// Registration Routes (Registered to mux)
	mux.HandleFunc("/register/begin", func(w http.ResponseWriter, r *http.Request) {
		handlers.BeginRegistration(w, r, webAuthnInstance)
	})
	mux.HandleFunc("/register/finish", func(w http.ResponseWriter, r *http.Request) {
		handlers.FinishRegistration(w, r, webAuthnInstance)
	})

	// Login Routes (Registered to mux)
	mux.HandleFunc("/login/begin", func(w http.ResponseWriter, r *http.Request) {
		handlers.BeginLogin(w, r, webAuthnInstance)
	})
	mux.HandleFunc("/login/finish", func(w http.ResponseWriter, r *http.Request) {
		handlers.FinishLogin(w, r, webAuthnInstance)
	})

	mux.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("🔥 ADMIN DATA: top secret"))
	})

	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("👤 USER DATA: general access"))
	})

	mux.HandleFunc("/auth/refresh", handlers.RefreshToken)
	mux.HandleFunc("/auth/logout", handlers.Logout)

	// Protected Route
	// Wrap the secretHandler with JWTMiddleware
	mux.HandleFunc("/api/secret-data", handlers.JWTMiddleware(secretHandler))

	// Serve frontend (index.html) at root
	mux.Handle("/", fileServer)

	// Start the server using 'mux'
	log.Println("Server started at http://localhost:8080")
	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}
}
