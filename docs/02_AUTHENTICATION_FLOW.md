# Luồng Authentication - JWT với RSA Asymmetric Encryption

## 📋 Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Luồng Đăng Ký (Register)](#1-luồng-đăng-ký-register)
3. [Luồng Đăng Nhập (Login)](#2-luồng-đăng-nhập-login)
4. [Luồng Xác Thực Request (Authentication)](#3-luồng-xác-thực-request-authentication)
5. [Luồng Làm Mới Token (Refresh Token)](#4-luồng-làm-mới-token-refresh-token)
6. [Luồng Đăng Xuất (Logout)](#5-luồng-đăng-xuất-logout)
7. [Luồng Key Rotation](#6-luồng-key-rotation)
8. [Security Features](#security-features)

---

## 🎯 Tổng Quan

Hệ thống sử dụng **JWT (JSON Web Token)** với **RSA Asymmetric Encryption** để xác thực người dùng. Điểm đặc biệt:

- ✅ **Mỗi user có cặp khóa RSA riêng** (2048 bits)
- ✅ **Private Key** ký JWT, **Public Key** verify JWT
- ✅ **Access Token** (short-lived: 1 hour)
- ✅ **Refresh Token** (long-lived: 7 days)
- ✅ **HTTP-Only Cookies** cho Refresh Token (XSS protection)
- ✅ **Key Rotation** và **Token Revocation**
- ✅ **Stateless Authentication** cho Access Token

---

## 1. Luồng Đăng Ký (Register)

### 📊 Sequence Diagram

```
Client                Controller            AuthService         UsersService      KeyPairsService      Database
  │                        │                     │                    │                  │                │
  │ POST /auth/register    │                     │                    │                  │                │
  ├───────────────────────>│                     │                    │                  │                │
  │ {username, email,      │                     │                    │                  │                │
  │  password, role}       │                     │                    │                  │                │
  │                        │                     │                    │                  │                │
  │                        │ register(dto)       │                    │                  │                │
  │                        ├────────────────────>│                    │                  │                │
  │                        │                     │                    │                  │                │
  │                        │                     │ hashPassword()     │                  │                │
  │                        │                     │ (bcrypt)           │                  │                │
  │                        │                     ├───────┐            │                  │                │
  │                        │                     │       │            │                  │                │
  │                        │                     │<──────┘            │                  │                │
  │                        │                     │                    │                  │                │
  │                        │                     │ getRoleId(role)    │                  │                │
  │                        │                     ├───────────────────>│                  │                │
  │                        │                     │                    │  SELECT role     │                │
  │                        │                     │                    ├─────────────────>│                │
  │                        │                     │                    │<─────────────────┤                │
  │                        │                     │<───────────────────┤                  │                │
  │                        │                     │  roleId            │                  │                │
  │                        │                     │                    │                  │                │
  │                        │                     │ create(user)       │                  │                │
  │                        │                     ├───────────────────>│                  │                │
  │                        │                     │                    │  INSERT user     │                │
  │                        │                     │                    ├─────────────────>│                │
  │                        │                     │                    │<─────────────────┤                │
  │                        │                     │<───────────────────┤                  │                │
  │                        │                     │  user              │                  │                │
  │                        │                     │                    │                  │                │
  │                        │                     │ createKeyPair(userId)                 │                │
  │                        │                     ├──────────────────────────────────────>│                │
  │                        │                     │                    │                  │                │
  │                        │                     │                    │         Generate RSA Keys          │
  │                        │                     │                    │         (2048 bits)                 │
  │                        │                     │                    │                  ├────────┐       │
  │                        │                     │                    │                  │        │       │
  │                        │                     │                    │                  │<───────┘       │
  │                        │                     │                    │                  │                │
  │                        │                     │                    │                  │ INSERT key_pair│
  │                        │                     │                    │                  ├───────────────>│
  │                        │                     │                    │                  │<───────────────┤
  │                        │                     │<──────────────────────────────────────┤                │
  │                        │                     │  keyPair           │                  │                │
  │                        │                     │                    │                  │                │
  │                        │<────────────────────┤                    │                  │                │
  │                        │  user (without pwd) │                    │                  │                │
  │                        │                     │                    │                  │                │
  │<───────────────────────┤                    │                    │                  │                │
  │ 201 Created            │                    │                    │                  │                │
  │ {user}                 │                    │                    │                  │                │
```

### 🔍 Chi Tiết Các Bước

#### **Step 1: Client gửi request đăng ký**
```http
POST /auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecureP@ssw0rd",
  "role": "user"
}
```

#### **Step 2: Validate dữ liệu**
- DTO Validation (class-validator)
- Email format, password strength
- Username/email unique check

#### **Step 3: Hash password**
```typescript
// Sử dụng bcrypt với salt rounds = 10
const hashedPassword = await bcrypt.hash(password, 10);
// Output: $2b$10$XYZ...
```

#### **Step 4: Lấy Role ID**
- Query role từ database
- Nếu không có role, dùng default 'user'

#### **Step 5: Tạo user trong database**
```sql
INSERT INTO users (id, username, email, password, role_id)
VALUES (UUID(), 'john_doe', 'john@example.com', '$2b$10$...', '<role_uuid>');
```

#### **Step 6: Generate RSA Key Pair**
```typescript
// Generate RSA 2048 bits
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
```

#### **Step 7: Lưu Key Pair vào database**
```sql
INSERT INTO key_pairs (id, userId, privateKey, publicKey, algorithm, isActive)
VALUES (UUID(), '<user_id>', '<private_key_pem>', '<public_key_pem>', 'RS256', TRUE);
```

#### **Step 8: Response**
```json
{
  "statusCode": 201,
  "message": "Đăng ký thành công",
  "data": {
    "id": "uuid",
    "username": "john_doe",
    "email": "john@example.com",
    "role": {
      "id": "uuid",
      "name": "user"
    }
  }
}
```

---

## 2. Luồng Đăng Nhập (Login)

### 📊 Sequence Diagram

```
Client              Controller          AuthService       KeyPairsService     Database
  │                      │                   │                   │               │
  │ POST /auth/login     │                   │                   │               │
  ├─────────────────────>│                   │                   │               │
  │ {email, password}    │                   │                   │               │
  │                      │                   │                   │               │
  │                      │ login(dto)        │                   │               │
  │                      ├──────────────────>│                   │               │
  │                      │                   │                   │               │
  │                      │                   │ validateUser()    │               │
  │                      │                   ├──────────┐        │               │
  │                      │                   │          │        │               │
  │                      │                   │  SELECT user      │               │
  │                      │                   ├──────────────────────────────────>│
  │                      │                   │<─────────────────────────────────┤
  │                      │                   │                   │               │
  │                      │                   │  bcrypt.compare() │               │
  │                      │                   ├──────────┐        │               │
  │                      │                   │          │        │               │
  │                      │                   │<─────────┘        │               │
  │                      │                   │                   │               │
  │                      │                   │ getOrCreateKeyPair(userId)        │
  │                      │                   ├──────────────────>│               │
  │                      │                   │                   │ SELECT key_pair
  │                      │                   │                   ├──────────────>│
  │                      │                   │                   │<──────────────┤
  │                      │                   │<──────────────────┤               │
  │                      │                   │                   │               │
  │                      │                   │ generateAccessToken()             │
  │                      │                   ├──────────┐        │               │
  │                      │                   │          │        │               │
  │                      │                   │  Sign JWT with    │               │
  │                      │                   │  Private Key      │               │
  │                      │                   │  (RS256)          │               │
  │                      │                   │<─────────┘        │               │
  │                      │                   │                   │               │
  │                      │                   │ generateRefreshToken()            │
  │                      │                   ├──────────┐        │               │
  │                      │                   │          │        │               │
  │                      │                   │  Sign JWT with    │               │
  │                      │                   │  Private Key      │               │
  │                      │                   │<─────────┘        │               │
  │                      │                   │                   │               │
  │                      │                   │ saveRefreshToken()│               │
  │                      │                   ├──────────────────────────────────>│
  │                      │                   │  INSERT refresh_token             │
  │                      │                   │<─────────────────────────────────┤
  │                      │                   │                   │               │
  │                      │<──────────────────┤                   │               │
  │                      │ {accessToken,     │                   │               │
  │                      │  refreshToken}    │                   │               │
  │                      │                   │                   │               │
  │                      │ Set Cookie        │                   │               │
  │                      │ (refreshToken)    │                   │               │
  │                      ├──────────┐        │                   │               │
  │                      │          │        │                   │               │
  │                      │<─────────┘        │                   │               │
  │                      │                   │                   │               │
  │<─────────────────────┤                   │                   │               │
  │ 200 OK               │                   │                   │               │
  │ Set-Cookie: refreshToken=...            │                   │               │
  │ {accessToken, user}  │                   │                   │               │
```

### 🔍 Chi Tiết Các Bước

#### **Step 1: Client gửi request login**
```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecureP@ssw0rd"
}
```

#### **Step 2: Validate credentials**
```typescript
// 1. Tìm user theo email
const user = await usersService.findByEmail(email);

// 2. So sánh password
const isValid = await bcrypt.compare(password, user.password);
```

#### **Step 3: Ensure Key Pair exists**
- Check xem user đã có active key pair chưa
- Nếu chưa → tạo mới

#### **Step 4: Generate Access Token**
```typescript
const payload = {
  sub: user.id,              // Subject (user ID)
  email: user.email,
  role: user.role.name,
  iat: Math.floor(Date.now() / 1000),  // Issued At
  exp: Math.floor(Date.now() / 1000) + 3600  // Expires In (1 hour)
};

// Sign với Private Key của user
const accessToken = jwt.sign(payload, privateKey, {
  algorithm: 'RS256'
});
```

**Access Token Structure:**
```
Header:
{
  "alg": "RS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "user-uuid",
  "email": "john@example.com",
  "role": "user",
  "iat": 1729152000,
  "exp": 1729155600
}

Signature:
RSASHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  privateKey
)
```

#### **Step 5: Generate Refresh Token**
```typescript
const payload = {
  sub: user.id,
  email: user.email,
  type: 'refresh',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 604800  // 7 days
};

const refreshToken = jwt.sign(payload, privateKey, {
  algorithm: 'RS256'
});
```

#### **Step 6: Save Refresh Token to Database**
```sql
INSERT INTO refresh_tokens (id, user_id, token, expires_at, is_revoked)
VALUES (UUID(), '<user_id>', '<refresh_token>', NOW() + INTERVAL 7 DAY, FALSE);
```

#### **Step 7: Set HTTP-Only Cookie**
```typescript
res.cookie('refreshToken', refreshToken, {
  httpOnly: true,        // Không thể access qua JavaScript
  secure: true,          // Chỉ gửi qua HTTPS
  sameSite: 'strict',    // CSRF protection
  maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days
  path: '/'
});
```

#### **Step 8: Response**
```json
{
  "statusCode": 200,
  "message": "Đăng nhập thành công",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600,
    "user": {
      "id": "uuid",
      "username": "john_doe",
      "email": "john@example.com",
      "role": {
        "id": "uuid",
        "name": "user"
      }
    }
  }
}
```

**Headers:**
```http
Set-Cookie: refreshToken=eyJhbGc...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800
```

---

## 3. Luồng Xác Thực Request (Authentication)

### 📊 Sequence Diagram

```
Client           Controller      JwtAuthGuard    JwtStrategy     KeyPairsService    Database
  │                   │                │               │                │               │
  │ GET /auth/profile │                │               │                │               │
  ├──────────────────>│                │               │                │               │
  │ Authorization:    │                │               │                │               │
  │ Bearer <token>    │                │               │                │               │
  │ x-client-id:      │                │               │                │               │
  │ <user_id>         │                │               │                │               │
  │                   │                │               │                │               │
  │                   │ @UseGuards     │               │                │               │
  │                   │ (JwtAuthGuard) │               │                │               │
  │                   ├───────────────>│               │                │               │
  │                   │                │               │                │               │
  │                   │                │ canActivate() │                │               │
  │                   │                ├──────────────>│                │               │
  │                   │                │               │                │               │
  │                   │                │               │ Extract x-client-id            │
  │                   │                │               ├────────┐       │               │
  │                   │                │               │        │       │               │
  │                   │                │               │<───────┘       │               │
  │                   │                │               │                │               │
  │                   │                │               │ getPublicKey(userId)           │
  │                   │                │               ├───────────────>│               │
  │                   │                │               │                │ SELECT key_pair
  │                   │                │               │                ├──────────────>│
  │                   │                │               │                │<──────────────┤
  │                   │                │               │<───────────────┤               │
  │                   │                │               │                │               │
  │                   │                │               │ Verify JWT     │               │
  │                   │                │               │ with PublicKey │               │
  │                   │                │               ├────────┐       │               │
  │                   │                │               │        │       │               │
  │                   │                │               │<───────┘       │               │
  │                   │                │               │                │               │
  │                   │                │               │ validate(payload)              │
  │                   │                │               ├────────┐       │               │
  │                   │                │               │        │       │               │
  │                   │                │               │ Check if key   │               │
  │                   │                │               │ still active   │               │
  │                   │                │               │        │       │               │
  │                   │                │               │<───────┘       │               │
  │                   │                │               │                │               │
  │                   │                │<──────────────┤                │               │
  │                   │                │  user object  │                │               │
  │                   │                │               │                │               │
  │                   │<───────────────┤               │                │               │
  │                   │  request.user  │               │                │               │
  │                   │                │               │                │               │
  │                   │ getProfile()   │               │                │               │
  │                   ├───────┐        │               │                │               │
  │                   │       │        │               │                │               │
  │                   │<──────┘        │               │                │               │
  │                   │                │               │                │               │
  │<──────────────────┤                │               │                │               │
  │ 200 OK            │                │               │                │               │
  │ {user profile}    │                │               │                │               │
```

### 🔍 Chi Tiết Các Bước

#### **Step 1: Client gửi request với Access Token**
```http
GET /auth/profile
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
x-client-id: user-uuid-here
```

**Quan trọng:** Header `x-client-id` chứa user ID để system biết lấy public key nào để verify.

#### **Step 2: JwtAuthGuard kích hoạt**
```typescript
@UseGuards(JwtAuthGuard)
@Get('profile')
async getProfile(@CurrentUser() user: any) {
  return user;
}
```

#### **Step 3: JwtStrategy extract và verify token**

**3.1. Extract token từ Authorization header:**
```typescript
const token = request.headers.authorization?.split(' ')[1];
// Bearer eyJhbGc... → eyJhbGc...
```

**3.2. Extract user ID từ x-client-id:**
```typescript
const clientId = request.headers['x-client-id'];
```

**3.3. Get Public Key:**
```typescript
const publicKey = await keyPairsService.getPublicKey(clientId);
```

**3.4. Verify JWT:**
```typescript
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256']
});
```

**Quá trình verify:**
```
1. Decode Header + Payload từ token
2. Lấy Signature từ token
3. Tính lại signature: RSASHA256(header.payload, publicKey)
4. So sánh signature → nếu khớp → valid
5. Check expiration time
```

#### **Step 4: Validate payload**
```typescript
async validate(payload: any) {
  // 1. Tìm user
  const user = await usersService.findById(payload.sub);
  
  // 2. Check key pair còn active không
  const activeKey = await keyPairsService.getActiveKeyPair(user.id);
  if (!activeKey) {
    throw new UnauthorizedException('Key revoked');
  }
  
  // 3. Return user object
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role
  };
}
```

#### **Step 5: Attach user to request**
```typescript
// User object được attach vào request
request.user = validatedUser;

// Controller có thể access qua @CurrentUser()
@Get('profile')
async getProfile(@CurrentUser() user: any) {
  return user;
}
```

#### **Step 6: Response**
```json
{
  "statusCode": 200,
  "data": {
    "id": "uuid",
    "email": "john@example.com",
    "username": "john_doe",
    "role": {
      "id": "uuid",
      "name": "user"
    },
    "canEdit": false
  }
}
```

### ❌ Error Cases

**1. Token missing:**
```json
{
  "statusCode": 401,
  "message": "Unauthorized"
}
```

**2. Invalid token:**
```json
{
  "statusCode": 401,
  "message": "Invalid token"
}
```

**3. Token expired:**
```json
{
  "statusCode": 401,
  "message": "Token expired"
}
```

**4. Key revoked:**
```json
{
  "statusCode": 401,
  "message": "Key pair has been revoked. Please login again."
}
```

---

## 4. Luồng Làm Mới Token (Refresh Token)

### 📊 Sequence Diagram

```
Client           Controller       AuthService      KeyPairsService     Database
  │                   │                │                   │               │
  │ POST /auth/refresh│                │                   │               │
  ├──────────────────>│                │                   │               │
  │ Cookie: refreshToken=...           │                   │               │
  │ x-client-id: <user_id>             │                   │               │
  │                   │                │                   │               │
  │                   │ Extract Cookie │                   │               │
  │                   ├────────┐       │                   │               │
  │                   │        │       │                   │               │
  │                   │<───────┘       │                   │               │
  │                   │                │                   │               │
  │                   │ refreshTokens()│                   │               │
  │                   ├───────────────>│                   │               │
  │                   │                │                   │               │
  │                   │                │ getPrivateKey()   │               │
  │                   │                ├──────────────────>│               │
  │                   │                │                   │ SELECT key_pair
  │                   │                │                   ├──────────────>│
  │                   │                │<──────────────────┤               │
  │                   │                │                   │               │
  │                   │                │ Verify refresh token              │
  │                   │                ├──────────┐        │               │
  │                   │                │          │        │               │
  │                   │                │<─────────┘        │               │
  │                   │                │                   │               │
  │                   │                │ Check token in DB │               │
  │                   │                ├──────────────────────────────────>│
  │                   │                │ SELECT refresh_token              │
  │                   │                │<─────────────────────────────────┤
  │                   │                │                   │               │
  │                   │                │ generateAccessToken()             │
  │                   │                ├──────────┐        │               │
  │                   │                │          │        │               │
  │                   │                │<─────────┘        │               │
  │                   │                │                   │               │
  │                   │                │ generateRefreshToken()            │
  │                   │                ├──────────┐        │               │
  │                   │                │          │        │               │
  │                   │                │<─────────┘        │               │
  │                   │                │                   │               │
  │                   │                │ Revoke old token  │               │
  │                   │                ├──────────────────────────────────>│
  │                   │                │ UPDATE is_revoked=TRUE            │
  │                   │                │<─────────────────────────────────┤
  │                   │                │                   │               │
  │                   │                │ Save new token    │               │
  │                   │                ├──────────────────────────────────>│
  │                   │                │ INSERT refresh_token              │
  │                   │                │<─────────────────────────────────┤
  │                   │                │                   │               │
  │                   │<───────────────┤                   │               │
  │                   │ {newAccessToken,│                  │               │
  │                   │  newRefreshToken}│                 │               │
  │                   │                │                   │               │
  │                   │ Update Cookie  │                   │               │
  │                   ├────────┐       │                   │               │
  │                   │        │       │                   │               │
  │                   │<───────┘       │                   │               │
  │                   │                │                   │               │
  │<──────────────────┤                │                   │               │
  │ 200 OK            │                │                   │               │
  │ Set-Cookie: refreshToken=<new>     │                   │               │
  │ {accessToken}     │                │                   │               │
```

### 🔍 Chi Tiết Các Bước

#### **Step 1: Client gửi request refresh**
```http
POST /auth/refresh
Authorization: Bearer <old_access_token>
Cookie: refreshToken=eyJhbGc...
x-client-id: user-uuid
```

**Note:** Client phải gửi cả access token cũ (dù đã expired) để verify user.

#### **Step 2: Extract refresh token từ cookie**
```typescript
const refreshToken = req.cookies?.refreshToken;

if (!refreshToken) {
  throw new UnauthorizedException('Refresh token not found');
}
```

#### **Step 3: Verify refresh token**
```typescript
// Lấy private key của user
const privateKey = await keyPairsService.getPrivateKey(userId);

// Verify token
const payload = await jwt.verify(refreshToken, privateKey, {
  algorithms: ['RS256']
});
```

#### **Step 4: Check token trong database**
```typescript
const storedToken = await refreshTokenRepository.findOne({
  where: {
    token: refreshToken,
    isRevoked: false
  }
});

if (!storedToken) {
  throw new UnauthorizedException('Invalid refresh token');
}

// Check expiration
if (storedToken.expiresAt < new Date()) {
  throw new UnauthorizedException('Refresh token expired');
}
```

#### **Step 5: Generate new tokens**
```typescript
// New Access Token (1 hour)
const newAccessToken = await generateAccessToken(user);

// New Refresh Token (7 days)
const newRefreshToken = await generateRefreshToken(user);
```

#### **Step 6: Revoke old refresh token**
```sql
UPDATE refresh_tokens 
SET is_revoked = TRUE 
WHERE token = '<old_refresh_token>';
```

#### **Step 7: Save new refresh token**
```sql
INSERT INTO refresh_tokens (id, user_id, token, expires_at)
VALUES (UUID(), '<user_id>', '<new_refresh_token>', NOW() + INTERVAL 7 DAY);
```

#### **Step 8: Update cookie và response**
```typescript
// Update cookie với new refresh token
res.cookie('refreshToken', newRefreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000
});

// Response
return {
  statusCode: 200,
  message: 'Token được làm mới thành công',
  data: {
    accessToken: newAccessToken,
    expiresIn: 3600
  }
};
```

---

## 5. Luồng Đăng Xuất (Logout)

### 📊 Sequence Diagram

```
Client           Controller       AuthService     KeyPairsService     Database
  │                   │                │                  │               │
  │ POST /auth/logout │                │                  │               │
  ├──────────────────>│                │                  │               │
  │ Cookie: refreshToken=...           │                  │               │
  │ Authorization: Bearer <token>      │                  │               │
  │                   │                │                  │               │
  │                   │ Extract tokens │                  │               │
  │                   ├────────┐       │                  │               │
  │                   │        │       │                  │               │
  │                   │<───────┘       │                  │               │
  │                   │                │                  │               │
  │                   │ logout()       │                  │               │
  │                   ├───────────────>│                  │               │
  │                   │                │                  │               │
  │                   │                │ Revoke refresh token             │
  │                   │                ├─────────────────────────────────>│
  │                   │                │ UPDATE is_revoked=TRUE           │
  │                   │                │<────────────────────────────────┤
  │                   │                │                  │               │
  │                   │                │ deactivateAllKeys()              │
  │                   │                ├─────────────────>│               │
  │                   │                │                  │ UPDATE key_pairs
  │                   │                │                  │ SET isActive=FALSE
  │                   │                │                  ├──────────────>│
  │                   │                │                  │<──────────────┤
  │                   │                │<─────────────────┤               │
  │                   │                │                  │               │
  │                   │<───────────────┤                  │               │
  │                   │                │                  │               │
  │                   │ Clear Cookie   │                  │               │
  │                   ├────────┐       │                  │               │
  │                   │        │       │                  │               │
  │                   │<───────┘       │                  │               │
  │                   │                │                  │               │
  │<──────────────────┤                │                  │               │
  │ 200 OK            │                │                  │               │
  │ Clear-Cookie      │                │                  │               │
  │ {message}         │                │                  │               │
```

### 🔍 Chi Tiết Các Bước

#### **Step 1: Client gửi request logout**
```http
POST /auth/logout
Authorization: Bearer <access_token>
Cookie: refreshToken=eyJhbGc...
x-client-id: user-uuid
```

#### **Step 2: Revoke refresh token**
```sql
UPDATE refresh_tokens
SET is_revoked = TRUE
WHERE token = '<refresh_token>' 
  AND user_id = '<user_id>'
  AND is_revoked = FALSE;
```

#### **Step 3: Deactivate tất cả key pairs (Secure Logout)**
```sql
UPDATE key_pairs
SET isActive = FALSE,
    revokedAt = NOW()
WHERE userId = '<user_id>'
  AND isActive = TRUE;
```

**Hiệu ứng:**
- ✅ Tất cả access tokens (kể cả chưa expired) đều invalid ngay lập tức
- ✅ Tất cả refresh tokens không thể refresh được nữa
- ✅ User bắt buộc phải login lại

#### **Step 4: Clear cookie**
```typescript
res.clearCookie('refreshToken', {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  path: '/'
});
```

#### **Step 5: Response**
```json
{
  "statusCode": 200,
  "message": "Đăng xuất thành công và đã revoke tất cả keys",
  "keysRevoked": true,
  "warning": "Tất cả tokens đã bị vô hiệu hóa. Vui lòng đăng nhập lại."
}
```

---

## 6. Luồng Key Rotation

### 📊 Sequence Diagram

```
Admin/System      KeyPairsService        Database
     │                    │                  │
     │ rotateKeyPair()    │                  │
     ├───────────────────>│                  │
     │                    │                  │
     │                    │ Deactivate old keys
     │                    ├─────────────────>│
     │                    │ UPDATE isActive=FALSE
     │                    │<─────────────────┤
     │                    │                  │
     │                    │ Generate new RSA │
     │                    ├────────┐         │
     │                    │        │         │
     │                    │<───────┘         │
     │                    │                  │
     │                    │ Save new key pair│
     │                    ├─────────────────>│
     │                    │ INSERT key_pairs │
     │                    │<─────────────────┤
     │                    │                  │
     │<───────────────────┤                  │
     │ {newKeyPair}       │                  │
```

### 🔍 Khi Nào Cần Key Rotation?

1. **Định kỳ** (recommended: mỗi 30-90 ngày)
2. **Security breach** (key bị lộ)
3. **User yêu cầu** (security concern)
4. **Compliance requirements**

### 📝 Implementation

```typescript
// Rotate key cho user
await keyPairsService.rotateKeyPair(userId);

// Hiệu ứng:
// - Tất cả tokens cũ invalid
// - User phải login lại
// - Tokens mới sẽ dùng key mới
```

---

## 🛡️ Security Features

### 1. **Asymmetric Encryption Benefits**

| Feature | Benefit |
|---------|---------|
| **Mỗi user 1 key pair** | Revoke một user không ảnh hưởng users khác |
| **Private key signing** | Chỉ server mới có thể tạo token |
| **Public key verification** | Có thể verify ở nhiều services |
| **Key rotation** | Invalidate tất cả tokens ngay lập tức |

### 2. **Token Storage**

| Token Type | Storage | Lifetime | Security |
|------------|---------|----------|----------|
| Access Token | Client (memory/localStorage) | 1 hour | Short-lived |
| Refresh Token | HTTP-Only Cookie | 7 days | XSS protected |

### 3. **Protection Mechanisms**

```typescript
// XSS Protection
httpOnly: true  // JavaScript không thể đọc cookie

// CSRF Protection
sameSite: 'strict'  // Cookie chỉ gửi từ same origin

// HTTPS Only
secure: true  // Cookie chỉ gửi qua HTTPS

// Man-in-the-Middle Protection
RS256 algorithm  // Asymmetric encryption
```

### 4. **Rate Limiting**

```typescript
@UseGuards(RoleThrottlerGuard)
// Admin: 1000 requests/hour
// User: 100 requests/hour
```

### 5. **Token Validation Layers**

```
1. JWT signature verification (cryptographic)
2. Expiration check
3. User existence check
4. Key pair active check
5. Refresh token revocation check
```

---

## 🎯 Best Practices

### ✅ DO

1. **Luôn verify key còn active** trước khi accept token
2. **Revoke keys khi logout** để invalidate tất cả tokens
3. **Rotate keys định kỳ** (30-90 ngày)
4. **Cleanup expired tokens** (scheduled job)
5. **Use HTTPS** trong production
6. **Log security events** (login, logout, key rotation)

### ❌ DON'T

1. **Không lưu private key ở client**
2. **Không share keys giữa users**
3. **Không dùng access token làm refresh token**
4. **Không bỏ qua x-client-id validation**
5. **Không expose private keys qua API**
6. **Không skip key active check**

---

## 📊 Token Lifecycle Summary

```
User Login
    ↓
Generate Key Pair (if not exists)
    ↓
Create Access Token (1h) + Refresh Token (7d)
    ↓
[Access Token Expires]
    ↓
Use Refresh Token → New Access Token
    ↓
[Refresh Token Expires or User Logout]
    ↓
Revoke Refresh Token + Deactivate Keys
    ↓
Require Re-login
```

---

*📝 Document Version: 1.0*  
*📅 Last Updated: October 17, 2025*  
*👤 Author: Authentication System Team*
