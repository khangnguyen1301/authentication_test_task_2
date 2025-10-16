# Kỹ Thuật JWT với Mã Hóa Bất Đối Xứng (RSA)

## 📋 Mục Lục

1. [Giới Thiệu JWT](#1-giới-thiệu-jwt)
2. [Mã Hóa Đối Xứng vs Bất Đối Xứng](#2-mã-hóa-đối-xứng-vs-bất-đối-xứng)
3. [RSA Algorithm](#3-rsa-algorithm)
4. [Cấu Trúc JWT với RS256](#4-cấu-trúc-jwt-với-rs256)
5. [Implementation Chi Tiết](#5-implementation-chi-tiết)
6. [Key Management](#6-key-management)
7. [Security Analysis](#7-security-analysis)
8. [Performance Considerations](#8-performance-considerations)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Giới Thiệu JWT

### 🎯 JWT là gì?

**JWT (JSON Web Token)** là một chuẩn mở (RFC 7519) định nghĩa cách truyền thông tin an toàn giữa các bên dưới dạng JSON object. Token được ký số để có thể verify và tin cậy.

### 📊 Cấu Trúc JWT

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ
     │                                              │                                                                                                                                                                                              │
     └──────────────── HEADER ─────────────────────┴────────────────────────────────────────────────── PAYLOAD ──────────────────────────────────────────────────────────────────────────────┴──────────────────────────────────────────────── SIGNATURE ─────────────────────────────────────────────
```

**Ba phần ngăn cách bởi dấu chấm (.):**

1. **Header** - Metadata về token
2. **Payload** - Dữ liệu (claims)
3. **Signature** - Chữ ký số

---

## 2. Mã Hóa Đối Xứng vs Bất Đối Xứng

### 🔐 Symmetric (Đối Xứng) - HS256

```
┌──────────────┐                          ┌──────────────┐
│              │      Secret Key          │              │
│    Server    │◄────────────────────────►│   Verifier   │
│              │    (Cùng 1 key)          │              │
└──────────────┘                          └──────────────┘
        │                                         │
        │ Sign JWT                                │ Verify JWT
        ▼                                         ▼
    HS256(                                    HS256(
      header.payload,                           header.payload,
      SECRET_KEY                                SECRET_KEY
    )                                         )
```

**Đặc điểm:**
- ✅ Nhanh (performance cao)
- ✅ Đơn giản
- ❌ Phải chia sẻ secret key
- ❌ Không phù hợp cho multi-service
- ❌ Revoke token khó khăn

**Use case:**
- Single server application
- Internal microservices (trusted network)

---

### 🔓 Asymmetric (Bất Đối Xứng) - RS256

```
┌──────────────┐                          ┌──────────────┐
│              │     Private Key          │              │
│    Server    │                          │   Verifier   │
│              │     Public Key           │              │
└──────────────┘────────────────────────► └──────────────┘
        │                                         │
        │ Sign JWT                                │ Verify JWT
        ▼                                         ▼
    RS256(                                    RS256(
      header.payload,                           header.payload,
      PRIVATE_KEY                               PUBLIC_KEY
    )                                         )
```

**Đặc điểm:**
- ✅ Private key chỉ server giữ (an toàn hơn)
- ✅ Public key có thể share (verify ở nhiều nơi)
- ✅ Revoke dễ dàng (revoke key pair)
- ✅ Phù hợp microservices
- ❌ Chậm hơn symmetric (3-10x)
- ❌ Phức tạp hơn

**Use case:**
- Multi-service architecture
- Third-party API integration
- High security requirements
- **Hệ thống của chúng ta** ✅

---

## 3. RSA Algorithm

### 🧮 Toán Học Đằng Sau RSA

RSA (Rivest-Shamir-Adleman) dựa trên tính chất của số nguyên tố lớn:

```
1. Chọn 2 số nguyên tố lớn: p, q
2. Tính n = p × q
3. Tính φ(n) = (p-1) × (q-1)
4. Chọn e: 1 < e < φ(n), gcd(e, φ(n)) = 1
5. Tính d: d × e ≡ 1 (mod φ(n))

Public Key: (e, n)
Private Key: (d, n)
```

**Ví dụ đơn giản (số nhỏ cho minh họa):**

```
p = 61, q = 53
n = 61 × 53 = 3233
φ(n) = 60 × 52 = 3120
e = 17 (chọn ngẫu nhiên, gcd(17, 3120) = 1)
d = 2753 (tính từ d × 17 ≡ 1 mod 3120)

Public Key: (17, 3233)
Private Key: (2753, 3233)
```

**Signing (Private Key):**
```
signature = message^d mod n
```

**Verification (Public Key):**
```
message = signature^e mod n
```

### 🔢 Key Size trong Production

| Key Size | Security Level | Use Case |
|----------|---------------|----------|
| **1024 bits** | ❌ Deprecated | Không dùng (broken) |
| **2048 bits** | ✅ Good | **Hệ thống hiện tại** |
| **3072 bits** | ✅ Better | High security |
| **4096 bits** | ✅ Best | Maximum security |

**Trade-off:**
- Key size lớn → bảo mật cao hơn
- Key size lớn → chậm hơn (exponential)

---

## 4. Cấu Trúc JWT với RS256

### 📦 Header

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**Base64URL Encoded:**
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
```

**Giải thích:**
- `alg`: Algorithm - RS256 (RSA + SHA256)
- `typ`: Type - JWT

---

### 📦 Payload

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "john@example.com",
  "role": "user",
  "iat": 1729152000,
  "exp": 1729155600
}
```

**Base64URL Encoded:**
```
eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciIsImlhdCI6MTcyOTE1MjAwMCwiZXhwIjoxNzI5MTU1NjAwfQ
```

**Standard Claims:**

| Claim | Name | Description |
|-------|------|-------------|
| `sub` | Subject | User ID |
| `iat` | Issued At | Timestamp khi tạo token |
| `exp` | Expiration | Timestamp hết hạn |
| `iss` | Issuer | Ai tạo token (optional) |
| `aud` | Audience | Token dành cho ai (optional) |
| `nbf` | Not Before | Token chỉ valid sau thời điểm này |
| `jti` | JWT ID | Unique ID của token |

**Custom Claims (hệ thống của chúng ta):**
- `email`: Email của user
- `role`: Vai trò (admin, user, moderator)
- `type`: Loại token (refresh) - chỉ có ở refresh token

---

### 📦 Signature

**Process:**

```javascript
// 1. Concatenate header.payload
const data = base64UrlEncode(header) + "." + base64UrlEncode(payload);

// 2. Hash với SHA256
const hash = SHA256(data);

// 3. Sign với Private Key (RSA)
const signature = RSA_SIGN(hash, privateKey);

// 4. Base64URL encode
const encodedSignature = base64UrlEncode(signature);
```

**Output:**
```
NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ
```

---

## 5. Implementation Chi Tiết

### 🔧 Generate RSA Key Pair

```typescript
import * as crypto from 'crypto';

/**
 * Generate RSA-2048 key pair
 * @returns {privateKey, publicKey} in PEM format
 */
function generateRSAKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,  // Key size: 2048 bits
    
    // Public key format
    publicKeyEncoding: {
      type: 'spki',       // SubjectPublicKeyInfo (standard)
      format: 'pem'       // Base64 encoded with headers
    },
    
    // Private key format
    privateKeyEncoding: {
      type: 'pkcs8',      // PKCS#8 (standard)
      format: 'pem',      // Base64 encoded with headers
      // cipher: 'aes-256-cbc',  // Optional: encrypt private key
      // passphrase: 'secret'     // Optional: passphrase for encryption
    }
  });

  return { privateKey, publicKey };
}
```

**Output Example:**

**Private Key (PEM format):**
```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGKz5x7sH1WQJM
qhOJF9xG3pNmILf4v1MH3xV3pBYQ1xVmFNY6Q0m5xH3pNmILf4v1MH3xV3pBYQ1x
VmFNY6Q0m5xH3pNmILf4v1MH3xV3pBYQ1xVmFNY6Q0m5xH3pNmILf4v1MH3xV3pB
... (nhiều dòng) ...
-----END PRIVATE KEY-----
```

**Public Key (PEM format):**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxisOcf7B9VkCTKoTiRfc
Rt6TZiC3+L9TB98Vd6QWENcVZhTWOkNJucR96TZiC3+L9TB98Vd6QWENcVZhTWOk
NJucR96TZiC3+L9TB98Vd6QWENcVZhTWOkNJucR96TZiC3+L9TB98Vd6QWENQIDA
... (nhiều dòng) ...
-----END PUBLIC KEY-----
```

---

### 🔧 Sign JWT (Create Token)

```typescript
import * as jwt from 'jsonwebtoken';

interface JwtPayload {
  sub: string;      // User ID
  email: string;
  role: string;
}

/**
 * Sign JWT với Private Key (RS256)
 */
async function signJWT(
  payload: JwtPayload,
  privateKey: string,
  expiresIn: number = 3600  // 1 hour
): Promise<string> {
  
  const options: jwt.SignOptions = {
    algorithm: 'RS256',       // RSA + SHA256
    expiresIn: `${expiresIn}s`,
    issuer: 'auth-system',    // Optional: issuer
    audience: 'api-server'    // Optional: audience
  };

  return new Promise((resolve, reject) => {
    jwt.sign(payload, privateKey, options, (err, token) => {
      if (err) reject(err);
      else resolve(token!);
    });
  });
}
```

**Usage:**

```typescript
const payload = {
  sub: 'user-uuid-123',
  email: 'john@example.com',
  role: 'user'
};

const privateKey = await keyPairsService.getPrivateKey(userId);
const token = await signJWT(payload, privateKey, 3600);

console.log(token);
// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

### 🔧 Verify JWT (Validate Token)

```typescript
import * as jwt from 'jsonwebtoken';

interface VerifyResult {
  valid: boolean;
  payload?: JwtPayload;
  error?: string;
}

/**
 * Verify JWT với Public Key (RS256)
 */
async function verifyJWT(
  token: string,
  publicKey: string
): Promise<VerifyResult> {
  
  const options: jwt.VerifyOptions = {
    algorithms: ['RS256'],     // Chỉ accept RS256
    issuer: 'auth-system',     // Must match issuer khi sign
    audience: 'api-server'     // Must match audience khi sign
  };

  return new Promise((resolve) => {
    jwt.verify(token, publicKey, options, (err, decoded) => {
      if (err) {
        resolve({
          valid: false,
          error: err.message
        });
      } else {
        resolve({
          valid: true,
          payload: decoded as JwtPayload
        });
      }
    });
  });
}
```

**Usage:**

```typescript
const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...';
const publicKey = await keyPairsService.getPublicKey(userId);

const result = await verifyJWT(token, publicKey);

if (result.valid) {
  console.log('Token valid!');
  console.log('User ID:', result.payload.sub);
  console.log('Email:', result.payload.email);
  console.log('Role:', result.payload.role);
} else {
  console.error('Token invalid:', result.error);
}
```

**Possible Errors:**

| Error | Reason |
|-------|--------|
| `jwt malformed` | Token format không đúng |
| `jwt signature is invalid` | Signature không khớp (wrong key hoặc tampered) |
| `jwt expired` | Token đã hết hạn |
| `jwt not active` | Token chưa đến thời gian active (nbf) |
| `invalid issuer` | Issuer không khớp |
| `invalid audience` | Audience không khớp |

---

### 🔧 Complete Implementation trong NestJS

```typescript
// key-pairs.service.ts
@Injectable()
export class KeyPairsService {
  
  /**
   * Generate và save RSA key pair
   */
  async createKeyPair(userId: string): Promise<KeyPairResult> {
    // 1. Deactivate old keys
    await this.deactivateAllKeys(userId);

    // 2. Generate new RSA keys
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // 3. Save to database
    const keyPair = this.keyPairRepository.create({
      userId,
      privateKey,
      publicKey,
      algorithm: 'RS256',
      isActive: true
    });

    const saved = await this.keyPairRepository.save(keyPair);

    return {
      id: saved.id,
      publicKey: saved.publicKey,
      privateKey: saved.privateKey,
      algorithm: saved.algorithm
    };
  }

  /**
   * Get active private key for signing
   */
  async getPrivateKey(userId: string): Promise<string | null> {
    const keyPair = await this.keyPairRepository.findOne({
      where: { userId, isActive: true },
      order: { createdAt: 'DESC' }
    });

    return keyPair?.privateKey || null;
  }

  /**
   * Get active public key for verification
   */
  async getPublicKey(userId: string): Promise<string | null> {
    const keyPair = await this.keyPairRepository.findOne({
      where: { userId, isActive: true },
      order: { createdAt: 'DESC' }
    });

    return keyPair?.publicKey || null;
  }

  /**
   * Deactivate all keys (revoke all tokens)
   */
  async deactivateAllKeys(userId: string): Promise<void> {
    await this.keyPairRepository.update(
      { userId, isActive: true },
      { isActive: false, revokedAt: new Date() }
    );
  }
}
```

```typescript
// auth.service.ts
@Injectable()
export class AuthService {
  
  /**
   * Generate Access Token
   */
  async generateAccessToken(user: User): Promise<string> {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role.name
    };

    // Get user's private key
    const privateKey = await this.keyPairsService.getPrivateKey(user.id);

    if (!privateKey) {
      throw new UnauthorizedException('User key pair not found');
    }

    // Sign JWT with private key
    return await this.jwtService.signAsync(payload, {
      privateKey: privateKey,
      algorithm: 'RS256',
      expiresIn: '1h'  // 1 hour
    });
  }

  /**
   * Generate Refresh Token
   */
  async generateRefreshToken(user: User): Promise<string> {
    const payload = {
      sub: user.id,
      email: user.email,
      type: 'refresh'
    };

    const privateKey = await this.keyPairsService.getPrivateKey(user.id);

    if (!privateKey) {
      throw new UnauthorizedException('User key pair not found');
    }

    return await this.jwtService.signAsync(payload, {
      privateKey: privateKey,
      algorithm: 'RS256',
      expiresIn: '7d'  // 7 days
    });
  }
}
```

```typescript
// jwt.strategy.ts
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly usersService: UsersService,
    private readonly keyPairsService: KeyPairsService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      
      // Dynamic secret/key based on user
      secretOrKeyProvider: async (request, rawJwtToken, done) => {
        try {
          // Extract user ID from x-client-id header
          const userId = request.headers['x-client-id'];

          if (!userId) {
            return done(new UnauthorizedException('x-client-id required'), null);
          }

          // Get user's public key for verification
          const publicKey = await this.keyPairsService.getPublicKey(userId);

          if (!publicKey) {
            return done(new UnauthorizedException('Key not found'), null);
          }

          done(null, publicKey);
        } catch (error) {
          done(error, null);
        }
      },
      
      algorithms: ['RS256']
    });
  }

  async validate(payload: any) {
    // Additional validation
    const user = await this.usersService.findById(payload.sub);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // CRITICAL: Check if key still active
    const activeKey = await this.keyPairsService.getActiveKeyPair(user.id);

    if (!activeKey) {
      throw new UnauthorizedException('Key revoked. Please login again.');
    }

    return {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role
    };
  }
}
```

---

## 6. Key Management

### 🔑 Key Lifecycle

```
┌────────────────────────────────────────────────────────┐
│                    KEY LIFECYCLE                       │
├────────────────────────────────────────────────────────┤
│                                                        │
│  1. GENERATION                                         │
│     ↓                                                  │
│     User Register/Login → Create Key Pair             │
│     ↓                                                  │
│  2. ACTIVE USAGE                                       │
│     ↓                                                  │
│     Sign JWT tokens with Private Key                  │
│     Verify JWT tokens with Public Key                 │
│     ↓                                                  │
│  3. ROTATION (Optional, every 30-90 days)             │
│     ↓                                                  │
│     Create new Key Pair                               │
│     Deactivate old Key Pair                           │
│     ↓                                                  │
│  4. REVOCATION                                         │
│     ↓                                                  │
│     - User logout (secure)                            │
│     - Security breach                                 │
│     - Admin action                                    │
│     ↓                                                  │
│     Set isActive = FALSE                              │
│     All tokens become invalid immediately             │
│     ↓                                                  │
│  5. CLEANUP (Scheduled)                               │
│     ↓                                                  │
│     Delete old inactive keys (keep for audit)         │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### 🔄 Key Rotation Strategy

**Khi nào cần rotate?**

1. **Định kỳ**: Mỗi 30-90 ngày
2. **Security incident**: Key bị lộ
3. **Compliance**: Yêu cầu của tổ chức
4. **User request**: User lo ngại về security

**Implementation:**

```typescript
@Cron('0 0 * * 0')  // Mỗi Chủ Nhật lúc 00:00
async rotateExpiredKeys() {
  // Get all keys > 90 days old
  const oldKeys = await this.keyPairRepository
    .createQueryBuilder('kp')
    .where('kp.isActive = :active', { active: true })
    .andWhere('kp.createdAt < :date', {
      date: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)
    })
    .getMany();

  // Rotate each
  for (const key of oldKeys) {
    await this.rotateKeyPair(key.userId);
    
    // Notify user
    await this.notificationService.sendEmail(key.userId, {
      subject: 'Security Key Rotated',
      message: 'Your security keys have been rotated. Please login again.'
    });
  }
}
```

### 🗄️ Key Storage Best Practices

**1. Database Encryption:**

```typescript
// Encrypt private key before saving
import * as crypto from 'crypto';

const ENCRYPTION_KEY = process.env.KEY_ENCRYPTION_SECRET;

function encryptPrivateKey(privateKey: string): string {
  const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptPrivateKey(encryptedKey: string): string {
  const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
  let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
```

**2. Access Control:**

```typescript
// Chỉ service backend mới có thể access private key
// NEVER expose private key qua API

@Get('keys/:keyId/private')  // ❌ NEVER DO THIS!
async getPrivateKey(@Param('keyId') keyId: string) {
  // This is a security vulnerability!
  return this.keyPairsService.getPrivateKey(keyId);
}

// ✅ Correct: Public key có thể share
@Get('keys/:userId/public')
async getPublicKey(@Param('userId') userId: string) {
  return this.keyPairsService.getPublicKey(userId);
}
```

**3. Audit Logging:**

```typescript
@Injectable()
export class KeyPairsService {
  
  async createKeyPair(userId: string): Promise<KeyPairResult> {
    // ... create key logic ...

    // Log event
    await this.auditLogger.log({
      action: 'KEY_PAIR_CREATED',
      userId,
      timestamp: new Date(),
      metadata: { keyId: keyPair.id }
    });

    return keyPair;
  }

  async deactivateAllKeys(userId: string): Promise<void> {
    // ... deactivate logic ...

    // Log event
    await this.auditLogger.log({
      action: 'KEYS_REVOKED',
      userId,
      timestamp: new Date(),
      reason: 'USER_LOGOUT'
    });
  }
}
```

---

## 7. Security Analysis

### 🛡️ Threat Model

| Threat | Mitigation | Implementation |
|--------|------------|----------------|
| **Token Theft (XSS)** | HTTP-Only Cookies | Refresh token trong cookie |
| **Token Theft (Network)** | HTTPS Only | `secure: true` |
| **CSRF Attack** | SameSite Cookie | `sameSite: 'strict'` |
| **Token Replay** | Short expiration | Access token: 1h |
| **Key Compromise** | Key Rotation | Rotate mỗi 90 ngày |
| **Mass Revocation** | Per-user keys | Revoke một user không ảnh hưởng khác |
| **Token Tampering** | RSA Signature | Verify signature |
| **Man-in-the-Middle** | Asymmetric encryption | Public key verification |

### 🔒 Security Advantages của RSA

**1. Key Separation:**
```
┌─────────────────────────────────────────────┐
│              Server (Private Key)           │
│  - Sign tokens                              │
│  - Never shared                             │
│  - Stored securely in database              │
└─────────────────────────────────────────────┘
                    │
                    │ Token
                    ▼
┌─────────────────────────────────────────────┐
│           Verifiers (Public Key)            │
│  - Multiple services can verify             │
│  - Can be shared publicly                   │
│  - No risk if leaked                        │
└─────────────────────────────────────────────┘
```

**2. Granular Revocation:**
```typescript
// Revoke một user → không ảnh hưởng users khác
await keyPairsService.deactivateAllKeys('user-123');

// User 123's tokens → invalid
// Other users' tokens → still valid
```

**3. Multiple Verifiers:**
```
                  ┌─────────────────┐
                  │  Auth Service   │
                  │  (Sign tokens)  │
                  └────────┬────────┘
                           │
                           │ Public Keys
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  API Gateway  │  │  User Service │  │  Order Service│
│  (Verify)     │  │  (Verify)     │  │  (Verify)     │
└───────────────┘  └───────────────┘  └───────────────┘
```

### 🎯 Attack Scenarios & Defense

**Scenario 1: Attacker steals Access Token**

```
Attacker: Có access token
Defense: 
  1. Token chỉ valid 1 hour → limited time window
  2. Revoke key → token invalid ngay lập tức
  3. Monitor unusual activities → auto revoke
```

**Scenario 2: Attacker steals Private Key**

```
Attacker: Có private key của 1 user
Defense:
  1. Key rotation → old key invalid
  2. Chỉ ảnh hưởng 1 user (không phải toàn hệ thống)
  3. Detect và revoke key đó
  4. Other users không bị ảnh hưởng
```

**Scenario 3: XSS Attack**

```
Attacker: Inject malicious script
Defense:
  1. Access token trong memory → có thể bị đánh cắp
  2. Refresh token trong HTTP-Only cookie → KHÔNG thể access
  3. SameSite cookie → không gửi cross-origin
```

**Scenario 4: Database Breach**

```
Attacker: Access database, lấy private keys
Defense:
  1. Encrypt private keys trong database
  2. Rotate tất cả keys ngay lập tức
  3. Force re-login toàn bộ users
  4. Audit và investigate
```

---

## 8. Performance Considerations

### ⚡ Benchmark: RS256 vs HS256

```
Sign (1000 tokens):
  HS256: ~50ms
  RS256: ~500ms (10x slower)

Verify (1000 tokens):
  HS256: ~30ms
  RS256: ~100ms (3x slower)
```

### 🎯 Optimization Strategies

**1. Caching Public Keys:**

```typescript
@Injectable()
export class KeyPairsService {
  private publicKeyCache = new Map<string, { key: string; expires: number }>();

  async getPublicKey(userId: string): Promise<string | null> {
    // Check cache
    const cached = this.publicKeyCache.get(userId);
    if (cached && cached.expires > Date.now()) {
      return cached.key;
    }

    // Query database
    const keyPair = await this.keyPairRepository.findOne({
      where: { userId, isActive: true }
    });

    if (keyPair) {
      // Cache for 1 hour
      this.publicKeyCache.set(userId, {
        key: keyPair.publicKey,
        expires: Date.now() + 3600000
      });

      return keyPair.publicKey;
    }

    return null;
  }

  // Clear cache when key rotated/revoked
  clearCache(userId: string) {
    this.publicKeyCache.delete(userId);
  }
}
```

**2. Connection Pooling:**

```typescript
// TypeORM configuration
{
  type: 'mysql',
  host: 'localhost',
  port: 3306,
  database: 'auth_system',
  extra: {
    connectionLimit: 10,  // Connection pool size
  }
}
```

**3. Index Optimization:**

```sql
-- Composite index for faster lookup
CREATE INDEX idx_userId_isActive 
ON key_pairs (userId, isActive);

-- Covering index (include columns trong index)
CREATE INDEX idx_userId_isActive_publicKey
ON key_pairs (userId, isActive, publicKey(255));
```

**4. Lazy Loading:**

```typescript
// Chỉ load public key khi cần verify
// Private key chỉ load khi cần sign

@Entity('key_pairs')
export class KeyPair {
  @Column({ type: 'text', select: false })  // Không auto-load
  privateKey: string;

  @Column({ type: 'text' })  // Auto-load
  publicKey: string;
}
```

### 📊 Performance Metrics

**Expected Latency:**

| Operation | Latency | Notes |
|-----------|---------|-------|
| Generate Key Pair | 100-300ms | One-time per user |
| Sign JWT | 5-10ms | Per login/refresh |
| Verify JWT | 2-5ms | Per request |
| Database Query (cached) | <1ms | Hit cache |
| Database Query (miss) | 5-20ms | Hit database |

---

## 9. Troubleshooting

### ❌ Common Errors

**Error 1: "jwt signature is invalid"**

```
Cause: 
  - Wrong public key used for verification
  - Token was tampered
  - Algorithm mismatch

Solution:
  1. Check x-client-id matches user ID
  2. Verify public key belongs to user
  3. Check algorithm is RS256
  4. Check token hasn't been modified
```

**Error 2: "jwt expired"**

```
Cause:
  - Access token > 1 hour old
  - Server time not synchronized

Solution:
  1. Use refresh token to get new access token
  2. Check server time (NTP sync)
  3. Don't extend expiration too much
```

**Error 3: "User key pair not found"**

```
Cause:
  - User doesn't have active key pair
  - Keys were revoked

Solution:
  1. Create new key pair for user
  2. User needs to login again
```

**Error 4: "Key pair has been revoked"**

```
Cause:
  - User logged out (secure logout)
  - Keys were rotated
  - Admin revoked keys

Solution:
  1. User must login again
  2. New keys will be generated
```

### 🔍 Debugging Tools

**1. Decode JWT (without verification):**

```typescript
import * as jwt from 'jsonwebtoken';

const token = 'eyJhbGc...';
const decoded = jwt.decode(token, { complete: true });

console.log('Header:', decoded.header);
console.log('Payload:', decoded.payload);
console.log('Signature:', decoded.signature);
```

**2. Verify Key Format:**

```typescript
function verifyKeyFormat(key: string): boolean {
  // Check PEM format
  if (key.includes('-----BEGIN') && key.includes('-----END')) {
    return true;
  }
  return false;
}

const privateKey = await keyPairsService.getPrivateKey(userId);
if (!verifyKeyFormat(privateKey)) {
  throw new Error('Invalid private key format');
}
```

**3. Test Key Pair:**

```typescript
async function testKeyPair(privateKey: string, publicKey: string) {
  // Create test token
  const testPayload = { test: 'data', iat: Math.floor(Date.now() / 1000) };
  const token = jwt.sign(testPayload, privateKey, { algorithm: 'RS256' });

  // Verify token
  try {
    const verified = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    console.log('✅ Key pair is valid!');
    return true;
  } catch (error) {
    console.error('❌ Key pair is invalid:', error.message);
    return false;
  }
}
```

**4. Logging:**

```typescript
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  
  constructor(/* ... */) {
    super({
      secretOrKeyProvider: async (request, rawJwtToken, done) => {
        const userId = request.headers['x-client-id'];
        
        // Log for debugging
        console.log('🔍 JWT Verification:', {
          userId,
          tokenLength: rawJwtToken?.length,
          timestamp: new Date().toISOString()
        });

        const publicKey = await this.keyPairsService.getPublicKey(userId);
        
        console.log('🔑 Public Key:', {
          found: !!publicKey,
          keyLength: publicKey?.length
        });

        done(null, publicKey);
      }
    });
  }
}
```

---

## 📚 References

### Standards & RFCs

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 3447 - RSA Cryptography Specifications](https://tools.ietf.org/html/rfc3447)

### Libraries

- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) - JWT implementation for Node.js
- [passport-jwt](https://github.com/mikenicholson/passport-jwt) - Passport strategy for JWT
- [Node.js crypto](https://nodejs.org/api/crypto.html) - Built-in cryptography

### Security Guidelines

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

---

## 📝 Summary

### ✅ Key Takeaways

1. **RSA Asymmetric Encryption** cho phép:
   - Private key để ký JWT (chỉ server)
   - Public key để verify JWT (có thể share)
   - Granular revocation (per-user)

2. **JWT Structure**:
   - Header (algorithm + type)
   - Payload (claims)
   - Signature (RSA-SHA256)

3. **Security**:
   - Each user có riêng key pair
   - Key rotation để invalidate tokens
   - HTTP-Only cookies cho refresh tokens
   - Multiple verification layers

4. **Performance**:
   - RS256 chậm hơn HS256 nhưng an toàn hơn
   - Caching để optimize
   - Trade-off giữa security và performance

5. **Best Practices**:
   - Never expose private keys
   - Rotate keys định kỳ
   - Short-lived access tokens
   - Audit logging
   - Error handling

---

*📝 Document Version: 1.0*  
*📅 Last Updated: October 17, 2025*  
*👤 Author: Authentication System Team*
