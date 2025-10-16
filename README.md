# 📊 ERD Diagrams - Visual Documentation

Tài liệu này chứa các sơ đồ ERD và flow diagrams sử dụng Mermaid syntax. Các diagram này có thể render trực tiếp trong GitHub, VS Code (với Mermaid extension), hoặc các Markdown viewers hỗ trợ Mermaid.

---

## 📐 Entity Relationship Diagram (ERD)

### Full Database Schema

```mermaid
erDiagram
    ROLES ||--o{ USERS : "has"
    USERS ||--o{ REFRESH_TOKENS : "owns"
    USERS ||--o{ KEY_PAIRS : "owns"

    ROLES {
        varchar(36) id PK "UUID"
        varchar(50) name UK "Role name"
        text description "Role description"
        boolean is_active "Active status"
        timestamp created_at
        timestamp updated_at
    }

    USERS {
        varchar(36) id PK "UUID"
        varchar(100) username UK "Username"
        varchar(255) email UK "Email"
        varchar(255) password "Hashed password"
        varchar(36) role_id FK "Role reference"
        timestamp created_at
        timestamp updated_at
    }

    REFRESH_TOKENS {
        varchar(36) id PK "UUID"
        varchar(36) user_id FK "User reference"
        text token "JWT refresh token"
        timestamp expires_at "Expiration time"
        boolean is_revoked "Revocation status"
        timestamp created_at
    }

    KEY_PAIRS {
        varchar(36) id PK "UUID"
        varchar(36) userId FK "User reference"
        text privateKey "RSA private key"
        text publicKey "RSA public key"
        varchar(20) algorithm "Algorithm (RS256)"
        boolean isActive "Active status"
        timestamp createdAt
        timestamp expiresAt "Expiration time"
        timestamp revokedAt "Revocation time"
    }
```

---

## 🔄 Authentication Flow Diagrams

### 1. Register Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant AC as AuthController
    participant AS as AuthService
    participant US as UsersService
    participant KS as KeyPairsService
    participant DB as Database

    C->>AC: POST /auth/register
    Note over C,AC: {username, email, password, role}

    AC->>AS: register(dto)
    AS->>AS: hashPassword(bcrypt)
    AS->>US: create(user)
    US->>DB: INSERT user
    DB-->>US: user
    US-->>AS: user

    AS->>KS: createKeyPair(userId)
    KS->>KS: Generate RSA-2048
    KS->>DB: INSERT key_pair
    DB-->>KS: keyPair
    KS-->>AS: keyPair

    AS-->>AC: user (without password)
    AC-->>C: 201 Created
    Note over C,AC: {id, username, email, role}
```

---

### 2. Login Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant AC as AuthController
    participant AS as AuthService
    participant KS as KeyPairsService
    participant DB as Database

    C->>AC: POST /auth/login
    Note over C,AC: {email, password}

    AC->>AS: login(dto)
    AS->>AS: validateUser()
    AS->>DB: SELECT user WHERE email
    DB-->>AS: user
    AS->>AS: bcrypt.compare(password)

    AS->>KS: getOrCreateKeyPair(userId)
    KS->>DB: SELECT active key_pair
    DB-->>KS: keyPair
    KS-->>AS: keyPair

    AS->>AS: generateAccessToken()
    Note over AS: Sign with Private Key
    AS->>AS: generateRefreshToken()
    Note over AS: Sign with Private Key

    AS->>DB: INSERT refresh_token
    DB-->>AS: saved

    AS-->>AC: {accessToken, refreshToken}
    AC->>AC: Set HTTP-Only Cookie
    AC-->>C: 200 OK
    Note over C,AC: Set-Cookie: refreshToken=...<br/>{accessToken, user}
```

---

### 3. Protected Route Access Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant G as JwtAuthGuard
    participant S as JwtStrategy
    participant KS as KeyPairsService
    participant US as UsersService
    participant DB as Database
    participant Con as Controller

    C->>G: GET /auth/profile
    Note over C,G: Authorization: Bearer token<br/>x-client-id: userId

    G->>S: canActivate()
    S->>S: Extract token from header
    S->>S: Extract userId from x-client-id

    S->>KS: getPublicKey(userId)
    KS->>DB: SELECT key_pair WHERE userId
    DB-->>KS: keyPair
    KS-->>S: publicKey

    S->>S: jwt.verify(token, publicKey)
    Note over S: Verify signature with RSA

    S->>US: findById(payload.sub)
    US->>DB: SELECT user WHERE id
    DB-->>US: user
    US-->>S: user

    S->>KS: getActiveKeyPair(userId)
    KS->>DB: SELECT WHERE isActive=true
    DB-->>KS: keyPair
    KS-->>S: keyPair

    alt Key is active
        S-->>G: user object
        G-->>Con: request.user = user
        Con-->>C: 200 OK {user profile}
    else Key revoked
        S-->>G: UnauthorizedException
        G-->>C: 401 Unauthorized
    end
```

---

### 4. Refresh Token Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant AC as AuthController
    participant AS as AuthService
    participant KS as KeyPairsService
    participant DB as Database

    C->>AC: POST /auth/refresh
    Note over C,AC: Cookie: refreshToken=...<br/>x-client-id: userId

    AC->>AC: Extract cookie
    AC->>AS: refreshTokens(userId, token)

    AS->>KS: getPrivateKey(userId)
    KS->>DB: SELECT key_pair
    DB-->>KS: keyPair
    KS-->>AS: privateKey

    AS->>AS: jwt.verify(token, privateKey)

    AS->>DB: SELECT refresh_token
    DB-->>AS: storedToken

    alt Token valid and not revoked
        AS->>AS: generateAccessToken()
        AS->>AS: generateRefreshToken()

        AS->>DB: UPDATE old token SET revoked=true
        AS->>DB: INSERT new refresh_token

        AS-->>AC: {accessToken, refreshToken}
        AC->>AC: Update Cookie
        AC-->>C: 200 OK
        Note over C,AC: New accessToken
    else Token invalid
        AS-->>AC: UnauthorizedException
        AC-->>C: 401 Unauthorized
    end
```

---

### 5. Logout Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant AC as AuthController
    participant AS as AuthService
    participant KS as KeyPairsService
    participant DB as Database

    C->>AC: POST /auth/logout
    Note over C,AC: Authorization: Bearer token<br/>Cookie: refreshToken

    AC->>AC: Extract refresh token
    AC->>AS: logout(userId, refreshToken)

    AS->>DB: UPDATE refresh_token SET revoked=true
    DB-->>AS: updated

    AS->>KS: deactivateAllKeys(userId)
    KS->>DB: UPDATE key_pairs SET isActive=false
    Note over KS,DB: All tokens become invalid
    DB-->>KS: updated
    KS-->>AS: done

    AS-->>AC: success message
    AC->>AC: Clear Cookie
    AC-->>C: 200 OK
    Note over C,AC: All tokens invalidated
```

---

### 6. Key Rotation Flow

```mermaid
sequenceDiagram
    participant Admin as Admin/System
    participant KS as KeyPairsService
    participant DB as Database
    participant NS as NotificationService
    participant User as User

    Admin->>KS: rotateKeyPair(userId)

    KS->>DB: UPDATE key_pairs SET isActive=false
    Note over KS,DB: Deactivate old keys
    DB-->>KS: updated

    KS->>KS: Generate new RSA-2048
    Note over KS: New private + public key

    KS->>DB: INSERT new key_pair
    DB-->>KS: newKeyPair

    KS-->>Admin: success

    Admin->>NS: notifyUser(userId, 'Keys rotated')
    NS->>User: Email notification
    Note over User: Please login again
```

---

## 🔐 JWT Token Structure

```mermaid
graph LR
    A[JWT Token] --> B[Header]
    A --> C[Payload]
    A --> D[Signature]

    B --> B1[Algorithm: RS256]
    B --> B2[Type: JWT]

    C --> C1[sub: User ID]
    C --> C2[email: Email]
    C --> C3[role: Role]
    C --> C4[iat: Issued At]
    C --> C5[exp: Expires At]

    D --> D1[RSA-SHA256]
    D --> D2[Signed with Private Key]
    D --> D3[Verified with Public Key]
```

---

## 🔑 Key Management Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created: User Register/Login
    Created --> Active: Set isActive=true
    Active --> Active: Sign/Verify JWT
    Active --> Rotating: Key Rotation Triggered
    Rotating --> Inactive: Create New Key
    Active --> Revoked: Logout/Security Event
    Inactive --> Archived: Cleanup Job
    Revoked --> Archived: Cleanup Job
    Archived --> [*]

    note right of Active
        - Sign Access Tokens
        - Sign Refresh Tokens
        - Verify with Public Key
    end note

    note right of Rotating
        - Every 30-90 days
        - Security breach
        - Compliance requirement
    end note

    note right of Revoked
        - All tokens invalid
        - User must re-login
    end note
```

---

## 🛡️ Security Layers

```mermaid
graph TB
    A[Incoming Request] --> B{Has JWT Token?}
    B -->|No| Z[401 Unauthorized]
    B -->|Yes| C{Extract x-client-id}
    C -->|Missing| Z
    C -->|Valid| D[Get Public Key]
    D --> E{Verify JWT Signature}
    E -->|Invalid| Z
    E -->|Valid| F{Check Token Expiration}
    F -->|Expired| Z
    F -->|Valid| G{User Exists?}
    G -->|No| Z
    G -->|Yes| H{Key Pair Active?}
    H -->|No| W[401 Key Revoked]
    H -->|Yes| I{Check User Role}
    I -->|Authorized| J[Access Granted]
    I -->|Unauthorized| Y[403 Forbidden]
```

---

## 🔄 Token Lifecycle

```mermaid
graph TD
    Start[User Login] --> Gen[Generate Key Pair if not exists]
    Gen --> Sign[Sign JWT with Private Key]
    Sign --> AT[Access Token - 1 hour]
    Sign --> RT[Refresh Token - 7 days]

    AT --> Use[Use for API Requests]
    Use --> Check{Token Expired?}
    Check -->|No| Use
    Check -->|Yes| Refresh[Use Refresh Token]

    Refresh --> Validate{Refresh Token Valid?}
    Validate -->|Yes| NewAT[New Access Token]
    Validate -->|No| Login[Re-login Required]

    NewAT --> Use

    RT --> RTCheck{RT Expired?}
    RTCheck -->|Yes| Login
    RTCheck -->|No| Refresh

    Use --> Logout{User Logout?}
    Logout -->|Yes| Revoke[Revoke All Keys]
    Revoke --> End[Tokens Invalidated]

    style AT fill:#90EE90
    style RT fill:#FFB6C1
    style Revoke fill:#FFB6C1
    style End fill:#FF6B6B
```

---

## 🏗️ System Architecture

```mermaid
graph TB
    subgraph Client Layer
        A[Browser]
        B[Mobile App]
        C[Postman]
    end

    subgraph API Layer
        D[AuthController]
        E[JwtAuthGuard]
        F[RolesGuard]
        G[RoleThrottlerGuard]
    end

    subgraph Service Layer
        H[AuthService]
        I[KeyPairsService]
        J[UsersService]
        K[RolesService]
    end

    subgraph Strategy Layer
        L[JwtStrategy]
        M[JwtRefreshStrategy]
    end

    subgraph Database Layer
        N[(MySQL)]
        O[roles]
        P[users]
        Q[refresh_tokens]
        R[key_pairs]
    end

    A --> D
    B --> D
    C --> D

    D --> E
    E --> F
    F --> G

    G --> H
    H --> I
    H --> J
    H --> K

    E --> L
    E --> M

    I --> N
    J --> N
    K --> N
    H --> N

    N --> O
    N --> P
    N --> Q
    N --> R

    style H fill:#FFD700
    style I fill:#FFD700
    style L fill:#87CEEB
    style N fill:#98FB98
```

---

## 📊 Performance Flow

```mermaid
graph LR
    A[Request] --> B{Public Key Cached?}
    B -->|Yes| C[Get from Cache - 1ms]
    B -->|No| D[Query Database - 20ms]
    D --> E[Cache for 1 hour]
    E --> F[Return Public Key]
    C --> F

    F --> G[Verify JWT - 3ms]
    G --> H{Valid?}
    H -->|Yes| I[Proceed - Total ~4ms]
    H -->|No| J[Reject - 401]

    style C fill:#90EE90
    style D fill:#FFB6C1
    style I fill:#90EE90
    style J fill:#FF6B6B
```

---

## 🔐 Encryption Comparison

```mermaid
graph TB
    subgraph Symmetric - HS256
        A1[Server] -->|Same Secret Key| A2[Sign JWT]
        A2 -->|Same Secret Key| A3[Verify JWT]
        A3 -.->|Risk: Key must be shared| A4[Other Services]
    end

    subgraph Asymmetric - RS256
        B1[Server] -->|Private Key| B2[Sign JWT]
        B2 -->|Public Key| B3[Verify JWT]
        B3 -.->|Safe: Public key can be shared| B4[Multiple Services]
        B5[API Gateway] -->|Public Key| B3
        B6[Microservice A] -->|Public Key| B3
    end

    style A1 fill:#FFB6C1
    style A4 fill:#FFB6C1
    style B1 fill:#90EE90
    style B4 fill:#90EE90
    style B5 fill:#90EE90
    style B6 fill:#90EE90
```

---

## 📈 Monitoring Dashboard Metrics

```mermaid
graph TB
    subgraph Authentication Metrics
        A1[Login Rate]
        A2[Failed Logins]
        A3[Registration Rate]
    end

    subgraph Token Metrics
        B1[Active Tokens]
        B2[Refresh Rate]
        B3[Token Errors]
    end

    subgraph Key Management
        C1[Active Keys]
        C2[Revoked Keys]
        C3[Key Rotation Events]
    end

    subgraph Performance
        D1[Response Time]
        D2[Database Queries]
        D3[Cache Hit Rate]
    end

    subgraph Security
        E1[Suspicious Activities]
        E2[Rate Limit Hits]
        E3[Unauthorized Attempts]
    end

    style A2 fill:#FFB6C1
    style B3 fill:#FFB6C1
    style C2 fill:#FFB6C1
    style E1 fill:#FF6B6B
    style E3 fill:#FF6B6B
```

---

## 🎯 Decision Flow: Which Token to Use?

```mermaid
graph TD
    A[Need Authentication?] -->|Yes| B{What type of action?}
    A -->|No| C[No token needed]

    B -->|API Request| D[Use Access Token]
    B -->|Access expired| E[Use Refresh Token]
    B -->|First time| F[Login to get tokens]

    D --> G{Token valid?}
    G -->|Yes| H[Process Request]
    G -->|No| I{Error type?}

    I -->|Expired| E
    I -->|Invalid Signature| F
    I -->|Key Revoked| F

    E --> J{Refresh valid?}
    J -->|Yes| K[Get new Access Token]
    J -->|No| F

    K --> D

    style H fill:#90EE90
    style F fill:#FFD700
    style K fill:#87CEEB
```
