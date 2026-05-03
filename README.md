# **Zero Trust Identity Provider (IdP)**

## **Category**
Identity & Access Management (IAM) / Security Engineering

## Category
Security Engineering

## How it Works
This is a Go-based authentication server that ditches traditional passwords for **Passkeys (WebAuthn)** and **JWT-based Authorization**. It serves as the central identity authority for the **Sentinel Go Security Proxy**, providing biometric-backed security and signed identity tokens.

## **How it Works**

* **Biometric Auth:** Users register and login using hardware security keys or built-in biometrics (Fingerprint/FaceID) via the WebAuthn API.
* **Stateless Identity:** Upon a successful handshake, the server issues a JWT (JSON Web Token) containing the user's identity and role.
* **Identity Propagation:** These signed tokens are recognized by the Sentinel Proxy, which validates the signature before allowing access to shielded routes.
* **Zero Trust:** The server trusts nothing by default. Every request to a protected route must prove identity via a valid, signed cryptographic header.

## **Central Pipeline Integration**

This IdP is the first step in the distributed security pipeline:
1. **Authentication:** User logs in here and receives a JWT.
2. **Verification:** Sentinel Proxy uses the shared secret key to verify the JWT signature.
3. **Observability:** User identity (e.g., "Bob") is extracted and sent to the **LumenLog Ingestor** for permanent audit logging in ClickHouse[cite: 3].

## **Project Structure**

* **`/handlers`**: The engine room. Contains the WebAuthn logic and JWT generation.
* **`/internal`**: Private crypto and storage logic.
* **`/db`**: Simple in-memory user persistence.
* **`/static`**: The frontend playground for testing the login flow.

## **Running the Project**

### **1. Spin up the server**
`go run main.go`

### **2. Access the UI**
Head to `http://localhost:8080`. Register a passkey, then try to access the "Top Secret Data."

### **3. Test the API via CLI (Windows/PowerShell)**
You can use the token generated on login to hit the protected proxy route directly:

`$headers = @{Authorization = "Bearer YOUR_TOKEN_HERE"}; Invoke-RestMethod -Uri "http://localhost:8081/api/secret-data" -Headers $headers`

## **Security Note**
To ensure the Sentinel Proxy accepts tokens from this IdP, ensure both projects use the same signing key: `your_ultra_secret_key_123`.

## **Tech Stack**
* **Go (Golang)**
* **WebAuthn** (Passkeys)
* **JWT** (Stateless Auth)
* **Vanilla JS** (Frontend)
