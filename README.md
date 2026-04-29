# Zero Trust Identity Provider (IdP) 

This is a Go-based authentication server that ditches traditional passwords for **Passkeys (WebAuthn)** and **JWT-based Authorization**. No more "Forgot Password" loops—just biometric security and signed tokens.

## How it Works

1.  **Biometric Auth:** Users register and login using hardware security keys or built-in biometrics (Fingerprint/FaceID) via the WebAuthn API.
2.  **Stateless Identity:** Upon a successful handshake, the server issues a JWT (JSON Web Token) containing the user's identity and role.
3.  **Role-Based Access (RBAC):** A custom Go middleware acts as the gatekeeper, decoding the JWT to ensure only "Admin" users can touch the most sensitive API endpoints.
4.  **Zero Trust:** The server trusts nothing by default. Every request to a protected route must prove identity via a valid, signed cryptographic header.

## Project Structure

* `/handlers`: The engine room. Contains the WebAuthn logic and JWT generation.
* `/internal`: Private crypto and storage logic.
* `/db`: Simple in-memory user persistence.
* `/static`: The frontend playground for testing the login flow.

## Running the Project

1.  **Spin up the server:**
    ```bash
    go run main.go
    ```
2.  **Access the UI:**
    Head to `http://localhost:8080`. Register a passkey, then try to access the "Top Secret Data."
3.  **Test the API via CLI:**
    You can grab the `token.txt` generated on login and hit the API directly:
    ```powershell
    $token = Get-Content token.txt
    curl.exe -H "Authorization: Bearer $token" http://localhost:8080/api/secret-data
    ```

## Tech Stack
* **Go (Golang)**
* **WebAuthn** (Passkeys)
* **JWT** (Stateless Auth)
* **Vanilla JS** (Frontend)