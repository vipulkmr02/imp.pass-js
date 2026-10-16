# Imp.pass C# / ASP.NET Core port

This folder contains a .NET 8 port of the imp.pass-js backend. The original TypeScript/Express implementation remains unchanged.

## Stack

- ASP.NET Core minimal APIs
- Google Cloud Firestore
- BCrypt password hashing
- PBKDF2-SHA256 key derivation
- AES-256-GCM password encryption

## Run locally

Install the .NET 8 SDK, then from this directory:

    dotnet restore
    dotnet run --project ImpPass.Api

Set the Firestore project and credentials before starting the API:

    export GOOGLE_CLOUD_PROJECT="your-firebase-project-id"
    export GOOGLE_APPLICATION_CREDENTIALS="/absolute/path/to/service-account.json"
    export FRONTEND_URL="http://localhost:4200"
    dotnet run --project ImpPass.Api

Use a service account with only the Firestore permissions this application needs. Do not commit service-account JSON, passwords, or production secrets.

The API listens on the URL printed by ASP.NET Core (commonly http://localhost:5000 or https://localhost:7000). Set ASPNETCORE_URLS=http://localhost:9000 if you need to use the same local port as the original backend.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | / | Health check |
| POST | /register | Register with email and password JSON fields |
| GET | /identify | Return the authenticated account email |
| GET | /initSession | Return the session ID |
| GET | /validateSession | Check a session |
| PUT | /new | Create an encrypted password record |
| GET | /password?pID=all | List and decrypt all records |
| GET | /password?pID=... | Retrieve one record |
| GET | /delete?pID=... | Delete a record |
| PUT | /update?pID=... | Update the password and/or its label |
| PUT | /changePassword | Change the master password and re-encrypt records |

After authenticating with email and password request headers, the API returns a Session response header. Send it on later requests as Authorization: Session <session-id>. Session lifetime is ten minutes and is refreshed on use.

## Security and migration notes

- Password labels are mapped to deterministic SHA-1 document IDs to retain the existing Firestore layout. SHA-1 is used only as a document-key mapping, not for password hashing.
- Account passwords are hashed with BCrypt. A per-user random salt is persisted for PBKDF2-SHA256 key derivation, and stored password values use AES-256-GCM with a fresh 12-byte nonce.
- The original JavaScript code derives its encryption key with a newly generated salt each time and does not persist that salt. This means old records are not reliably decryptable after a fresh login. The C# port fixes this for newly registered C# accounts; it is not a drop-in cryptographic migration for existing encrypted records.
- Existing Firestore users without a keySalt field need an explicit migration/export path before using the C# implementation. Do not assume existing records can be decrypted by this port.
- Configure CORS for the actual frontend origin before deployment. Use HTTPS in production, rate-limit registration/authentication, and consider a managed secret store for credentials.
- Password changes re-encrypt records sequentially. For production use, move this to a Firestore transaction or a recoverable migration workflow so a failure cannot leave a partially migrated collection.

## Interview talking points

- Why minimal APIs are a good fit for a small HTTP service, and when controllers become preferable.
- Why database and cryptography logic live outside endpoint handlers.
- Why BCrypt is used for authentication passwords while PBKDF2 derives an encryption key.
- Why AES-GCM needs a unique nonce and an authentication tag.
- Why the C# implementation calls out legacy-data compatibility rather than silently pretending two different key-derivation schemes are interchangeable.
