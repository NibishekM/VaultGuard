# VaultGuard — Zero-Knowledge Password Manager

VaultGuard is a zero-knowledge cybersecurity password manager designed to securely store, synchronize, and manage credentials with end-to-end client-side encryption. Plaintext passwords, unencrypted vault records, master passwords, and encryption keys never leave the client device or enter the backend database.

---

## Key Features

- **Zero-Knowledge Architecture:** All sensitive vault item data (service, username, password, notes, tags) is encrypted and decrypted exclusively on the client device using AES-256-GCM.
- **Client-Side Key Derivation:** Master passwords derive a 256-bit vault key using PBKDF2-HMAC-SHA256 with 600,000 iterations and a unique 32-byte cryptographic salt.
- **Cryptographic Canary Verification:** Master password validity is authenticated through an encrypted verification canary payload without transmitting or storing plaintext passwords or verifiers.
- **Multi-Device Session & Token Management:** Independent session tracking across browser and mobile contexts with single-use rotating refresh tokens, session revocation, and CSRF protection.
- **Monotonic Cross-Device Synchronization:** Versioned incremental sync engine (`syncVersion`) providing reliable updates and tombstone deletions without zombie records.
- **Encrypted Backup & Recovery:** Client-side encrypted JSON vault backup exports and imports with pre-commit cryptographic tag verification and conflict resolution strategies.
- **Contextual Security Assistant:** Local, deterministic password health analyzer providing actionable security recommendations and privacy-gated locked-state protection without external AI dependencies or network transmission.

---

## Tech Stack

### Frontend
- **Framework:** Next.js (App Router) & React 19
- **Language:** TypeScript
- **Styling:** Tailwind CSS & Radix/Base UI components
- **Cryptography:** Web Crypto API (SubtleCrypto) — AES-256-GCM, PBKDF2-HMAC-SHA256
- **Testing:** Custom zero-knowledge cryptographic & integration verification test suites

### Backend
- **Runtime:** Node.js
- **Framework:** Express 5
- **Language:** TypeScript
- **Database & ORM:** MySQL 8 with Prisma 7 (using `@prisma/adapter-mariadb`)
- **Authentication:** Argon2id password hashing, signed JSON Web Tokens (JWT), rotating refresh tokens stored as SHA-256 hashes
- **Security Middleware:** Helmet, CORS, Express Rate Limit, Cookie Parser

---

## Repository Structure

```
VaultGuard-GitHub/
├── frontend/                     # Next.js client-side application
│   ├── app/                      # App router pages and layouts
│   ├── components/               # React UI and vault management components
│   ├── lib/                      # Cryptography utilities, API client, sync logic
│   ├── public/                   # Static assets and icons
│   ├── scripts/                  # Verification and automated test suites
│   ├── .env.example              # Frontend environment template
│   ├── package.json              # Frontend dependencies and scripts
│   └── tsconfig.json             # TypeScript configuration
├── backend/                      # Express REST API backend
│   ├── prisma/                   # Prisma schema, configuration, and migrations
│   │   ├── migrations/           # SQL database migrations
│   │   └── schema.prisma         # Relational database schema
│   ├── src/                      # Backend application source code
│   │   ├── config/               # Database and environment configuration
│   │   ├── controllers/          # Request handlers (auth, vault, sync, devices)
│   │   ├── middleware/           # Authentication, error handling, validation
│   │   ├── routes/               # API endpoint definitions
│   │   ├── services/             # Core business logic and database interactions
│   │   ├── utils/                # JWT, hashing, cookie, and Zod schemas
│   │   └── server.ts             # Application entry point
│   ├── .env.example              # Backend environment template
│   ├── package.json              # Backend dependencies and scripts
│   └── tsconfig.json             # TypeScript configuration
├── .gitignore                    # Git ignore configuration
└── README.md                     # Project documentation
```

---

## Prerequisites

Before setting up VaultGuard, ensure you have the following installed:

- **Node.js:** v20.x or higher (recommended: v22 LTS or v26)
- **Package Manager:** `npm` (v10+) or `pnpm`
- **Database:** MySQL 8.0+ server running locally or accessible via network

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/VaultGuard.git
cd VaultGuard
```

---

### 2. Backend Setup

1. **Navigate to the backend directory:**
   ```bash
   cd backend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and set your database credentials and a secure random JWT secret (at least 32 bytes):
   ```env
   PORT=5000
   NODE_ENV=development
   FRONTEND_URL=http://localhost:3000

   DATABASE_HOST=localhost
   DATABASE_PORT=3306
   DATABASE_USER=your_mysql_username
   DATABASE_PASSWORD=your_mysql_password
   DATABASE_NAME=vaultguard_db

   DATABASE_URL="mysql://your_mysql_username:your_mysql_password@localhost:3306/vaultguard_db"

   JWT_SECRET=your_secure_random_jwt_secret_min_32_bytes
   JWT_EXPIRES_IN=15m
   ```

4. **Initialize MySQL Database:**
   Ensure MySQL is running, then create the database:
   ```sql
   CREATE DATABASE vaultguard_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```

5. **Run Prisma Migrations & Generate Client:**
   ```bash
   npx prisma migrate deploy
   npm run db:generate
   ```

---

### 3. Frontend Setup

1. **Navigate to the frontend directory:**
   ```bash
   cd ../frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   Copy `.env.example` to `.env.local`:
   ```bash
   cp .env.example .env.local
   ```
   Set the API URL to match your backend instance:
   ```env
   NEXT_PUBLIC_API_BASE_URL=http://localhost:5000
   ```

---

## Running the Application

### Development Mode

Open two terminal windows:

**Terminal 1 — Backend:**
```bash
cd backend
npm run dev
```
The backend server will start on `http://localhost:5000`.

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```
The frontend application will be accessible at `http://localhost:3000`.

---

## Testing & Verification

VaultGuard includes comprehensive test suites covering zero-knowledge client cryptography, session management, multi-device revocation, synchronization cursors, and backup imports.

### Frontend Unit & Verification Tests
```bash
cd frontend
npm test
```
To run specific zero-knowledge cryptographic tests:
```bash
npm run test:crypto
```

### Backend Type Check & Build
```bash
cd backend
npm run build
```

---

## Production Build

### Backend
Compile TypeScript to JavaScript (`dist/`):
```bash
cd backend
npm run build
npm start
```

### Frontend
Generate optimized Next.js production build:
```bash
cd frontend
npm run build
npm start
```

---

## Security Model Overview

1. **Zero-Knowledge Architecture:** Encryption keys are derived client-side via PBKDF2 with 600,000 iterations. The backend never receives raw passwords or cryptographic keys.
2. **Payload Protection:** All vault secrets are encrypted with AES-256-GCM. Authentication tags and initialization vectors are verified on every decryption.
3. **Defense-in-Depth Authentication:** Account passwords authenticate via Argon2id. Sessions are tracked individually with rotating, single-use refresh token hashes.
4. **Isolated Vault Processing:** The contextual assistant operates exclusively on decrypted in-memory vault data and terminates visibility immediately when the vault is locked.

---

## License

This project is licensed under the MIT License.
