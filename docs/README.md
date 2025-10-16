# 📚 Tài Liệu Hệ Thống Authentication

## 🎯 Tổng Quan

Đây là bộ tài liệu đầy đủ về hệ thống Authentication sử dụng JWT với mã hóa bất đối xứng RSA. Hệ thống được xây dựng trên NestJS, TypeScript, và MySQL.

---

## 📖 Danh Sách Tài Liệu

### 1. [ERD & Database Design](./01_ERD_DATABASE_DESIGN.md)
**Nội dung:**
- Sơ đồ quan hệ thực thể (ERD)
- Cấu trúc 4 bảng chính: `roles`, `users`, `refresh_tokens`, `key_pairs`
- Chi tiết về indexes, foreign keys, và constraints
- Database optimization và best practices
- Key rotation strategy ở tầng database

**Đối tượng:** Database Administrators, Backend Developers

**Thời gian đọc:** ~15 phút

---

### 2. [Authentication Flow](./02_AUTHENTICATION_FLOW.md)
**Nội dung:**
- 📊 Sequence diagrams chi tiết cho 6 luồng chính:
  1. Đăng ký (Register)
  2. Đăng nhập (Login)
  3. Xác thực Request (Authentication)
  4. Làm mới Token (Refresh Token)
  5. Đăng xuất (Logout)
  6. Key Rotation
- Step-by-step implementation
- HTTP request/response examples
- Error handling scenarios
- Security features và protection mechanisms

**Đối tượng:** Backend Developers, System Architects, Frontend Developers

**Thời gian đọc:** ~30 phút

---

### 3. [JWT với RSA - Technical Guide](./03_JWT_RSA_TECHNICAL_GUIDE.md)
**Nội dung:**
- JWT fundamentals
- So sánh Symmetric (HS256) vs Asymmetric (RS256)
- Toán học RSA và cryptography
- Cấu trúc JWT chi tiết (Header, Payload, Signature)
- Complete implementation code examples
- Key management lifecycle
- Security analysis và threat model
- Performance optimization
- Troubleshooting guide

**Đối tượng:** Senior Developers, Security Engineers, Technical Leads

**Thời gian đọc:** ~45 phút

---

## 🚀 Quick Start

### Đọc Theo Mục Đích

**Tôi muốn hiểu về database:**
→ Đọc [01_ERD_DATABASE_DESIGN.md](./01_ERD_DATABASE_DESIGN.md)

**Tôi muốn implement authentication:**
→ Đọc [02_AUTHENTICATION_FLOW.md](./02_AUTHENTICATION_FLOW.md)

**Tôi muốn hiểu sâu về JWT và RSA:**
→ Đọc [03_JWT_RSA_TECHNICAL_GUIDE.md](./03_JWT_RSA_TECHNICAL_GUIDE.md)

**Tôi là developer mới vào dự án:**
→ Đọc theo thứ tự: Document 1 → 2 → 3

**Tôi cần debug lỗi:**
→ Xem phần Troubleshooting trong [03_JWT_RSA_TECHNICAL_GUIDE.md](./03_JWT_RSA_TECHNICAL_GUIDE.md#9-troubleshooting)

---

## 🏗️ Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                            │
│  (Browser, Mobile App, Postman)                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ HTTP/HTTPS Requests
                            │ (Access Token, Refresh Token)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API GATEWAY / CONTROLLER                    │
│  - AuthController                                               │
│  - Guards: JwtAuthGuard, RolesGuard, RoleThrottlerGuard       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SERVICE LAYER                              │
│  - AuthService (login, register, refresh, logout)              │
│  - KeyPairsService (key generation, rotation, revocation)       │
│  - UsersService (user management)                               │
│  - RolesService (role management)                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      STRATEGY LAYER                              │
│  - JwtStrategy (token verification)                             │
│  - JwtRefreshStrategy (refresh token verification)              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DATABASE LAYER                             │
│  - MySQL Database                                               │
│    ├── roles                                                    │
│    ├── users                                                    │
│    ├── refresh_tokens                                           │
│    └── key_pairs                                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔑 Key Features

### ✅ Security
- ✨ **RSA-2048 Asymmetric Encryption** cho mỗi user
- 🔒 **HTTP-Only Cookies** cho Refresh Tokens (XSS protection)
- 🛡️ **CSRF Protection** với SameSite cookies
- 🚫 **Instant Token Revocation** thông qua key deactivation
- 🔄 **Key Rotation** để invalidate tất cả tokens
- 📊 **Rate Limiting** theo role (admin vs user)

### ⚡ Performance
- 💾 **Caching** public keys để giảm database queries
- 📈 **Database Indexing** tối ưu cho lookups
- 🔍 **Selective Loading** (private key chỉ load khi cần)
- ⏱️ **Short-lived Access Tokens** (1 hour)

### 🎯 Scalability
- 🌐 **Per-user Keys** → revoke một user không ảnh hưởng khác
- 🔌 **Stateless Authentication** với Access Tokens
- 🏢 **Microservices Ready** (share public keys)
- 📡 **Multiple Verifiers** có thể verify với cùng public key

### 🛠️ Developer Experience
- 📝 **TypeScript** với type safety
- 🎨 **NestJS** modular architecture
- 🧪 **Comprehensive Error Handling**
- 📚 **Detailed Documentation**
- 🔍 **Debugging Tools** và logging

---

## 🔐 Token Flow Diagram

```
┌─────────────┐
│   CLIENT    │
└──────┬──────┘
       │
       │ 1. POST /auth/login {email, password}
       ▼
┌─────────────────────────────────────────┐
│            AUTH SERVICE                 │
│  - Validate credentials                 │
│  - Get/Create RSA Key Pair             │
│  - Sign JWT with Private Key           │
└──────┬──────────────────────────────────┘
       │
       │ 2. Response
       │    - Access Token (1h)
       │    - Refresh Token (7d) in HTTP-Only Cookie
       ▼
┌─────────────┐
│   CLIENT    │
└──────┬──────┘
       │
       │ 3. GET /auth/profile
       │    Authorization: Bearer <access_token>
       │    x-client-id: <user_id>
       ▼
┌─────────────────────────────────────────┐
│          JWT STRATEGY                   │
│  - Extract token from header            │
│  - Get Public Key by x-client-id       │
│  - Verify signature with Public Key    │
│  - Check key still active              │
└──────┬──────────────────────────────────┘
       │
       │ 4. Request.user = validated user
       ▼
┌─────────────────────────────────────────┐
│          CONTROLLER                     │
│  - Access user from @CurrentUser()     │
│  - Return protected resource           │
└──────┬──────────────────────────────────┘
       │
       │ 5. Response {user profile}
       ▼
┌─────────────┐
│   CLIENT    │
└─────────────┘
```

---

## 📊 Database Tables Relationship

```
         roles (1)
            │
            │ role_id (FK)
            │
            ▼
         users (N)
            │
            ├────────────────────┐
            │                    │
            │ user_id (FK)       │ userId (FK)
            │                    │
            ▼                    ▼
    refresh_tokens (N)    key_pairs (N)
    - token               - privateKey
    - expires_at          - publicKey
    - is_revoked          - isActive
```

---

## 🧪 Testing Guide

### Test với Postman

**Collection đã có sẵn trong folder:** `postman/`

**Flow test cơ bản:**

1. **Register User:**
   ```
   POST {{baseUrl}}/auth/register
   Body: {
     "username": "testuser",
     "email": "test@example.com",
     "password": "Test@123",
     "role": "user"
   }
   ```

2. **Login:**
   ```
   POST {{baseUrl}}/auth/login
   Body: {
     "email": "test@example.com",
     "password": "Test@123"
   }
   
   Response: {
     "accessToken": "...",
     "user": {...}
   }
   
   Cookie: refreshToken=...
   ```

3. **Access Protected Route:**
   ```
   GET {{baseUrl}}/auth/profile
   Headers:
     - Authorization: Bearer <accessToken>
     - x-client-id: <user_id>
   ```

4. **Refresh Token:**
   ```
   POST {{baseUrl}}/auth/refresh
   Headers:
     - Authorization: Bearer <old_access_token>
     - x-client-id: <user_id>
   Cookie: refreshToken=...
   ```

5. **Logout:**
   ```
   POST {{baseUrl}}/auth/logout
   Headers:
     - Authorization: Bearer <access_token>
     - x-client-id: <user_id>
   Cookie: refreshToken=...
   ```

---

## 🔧 Environment Setup

### Required Environment Variables

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=root
DB_PASSWORD=your_password
DB_DATABASE=auth_system

# JWT
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=3600
JWT_REFRESH_SECRET=your-refresh-secret
JWT_REFRESH_EXPIRES_IN=604800

# App
NODE_ENV=development
PORT=3000

# Key Encryption (Optional)
KEY_ENCRYPTION_SECRET=your-key-encryption-secret
```

---

## 📈 Monitoring & Maintenance

### Scheduled Tasks

**1. Cleanup Expired Tokens:**
```typescript
@Cron('0 0 * * *')  // Daily at midnight
async cleanupExpiredTokens() {
  await this.authService.cleanupExpiredTokens();
}
```

**2. Cleanup Expired Keys:**
```typescript
@Cron('0 0 * * *')  // Daily at midnight
async cleanupExpiredKeys() {
  await this.keyPairsService.cleanupExpiredKeys();
}
```

**3. Key Rotation (Optional):**
```typescript
@Cron('0 0 * * 0')  // Weekly on Sunday
async rotateOldKeys() {
  // Rotate keys older than 90 days
}
```

### Metrics to Monitor

- 📊 **Authentication Rate**: Logins per hour
- 🚫 **Failed Login Attempts**: Potential attacks
- 🔑 **Active Keys**: Number of active key pairs
- 🔄 **Token Refresh Rate**: Refresh requests per hour
- ⏱️ **Average Response Time**: API performance
- 💾 **Database Size**: Growth rate
- ❌ **Error Rate**: System health

---

## 🐛 Common Issues & Solutions

### Issue 1: "jwt signature is invalid"
**Cause:** Wrong public key or tampered token  
**Solution:** Verify x-client-id, check if key is active

### Issue 2: "Key pair not found"
**Cause:** User doesn't have active key pair  
**Solution:** User needs to login again to generate new keys

### Issue 3: Token expired but can't refresh
**Cause:** Refresh token also expired or revoked  
**Solution:** User must login again

### Issue 4: Performance slow
**Cause:** Too many database queries  
**Solution:** Enable caching for public keys

---

## 📚 Further Reading

### Internal Documentation
- [API Documentation](../README.md)
- [Database Schema](../database/schema.sql)
- [Environment Setup](../.env.example)

### External Resources
- [JWT.io](https://jwt.io/) - Decode và debug JWT tokens
- [NestJS Documentation](https://docs.nestjs.com/)
- [TypeORM Documentation](https://typeorm.io/)
- [Node.js Crypto](https://nodejs.org/api/crypto.html)

### Security Standards
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 7519 - JWT](https://tools.ietf.org/html/rfc7519)
- [NIST Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

---

## 👥 Contribution Guidelines

### Code Style
- Follow NestJS best practices
- Use TypeScript strict mode
- Write descriptive commit messages
- Add JSDoc comments for public methods

### Security
- Never commit secrets/keys
- Always validate user input
- Log security events
- Follow principle of least privilege

### Testing
- Write unit tests for services
- Write e2e tests for critical flows
- Test error scenarios
- Test with expired tokens

---

## 📞 Support

### Questions?
- 📧 Email: dev-team@company.com
- 💬 Slack: #auth-system
- 📝 Issues: GitHub Issues

### Emergency Security Issues
- 🚨 Security Team: security@company.com
- 📞 On-call: +84-xxx-xxx-xxx

---

## 📝 Changelog

### Version 1.0.0 (October 17, 2025)
- ✨ Initial release
- ✅ RSA-2048 asymmetric encryption
- ✅ Per-user key pairs
- ✅ HTTP-Only cookies for refresh tokens
- ✅ Key rotation support
- ✅ Role-based access control
- ✅ Rate limiting
- ✅ Comprehensive documentation

---

## 📄 License

This documentation is proprietary and confidential.  
© 2025 Authentication System Team. All rights reserved.

---

*📝 Document Version: 1.0*  
*📅 Last Updated: October 17, 2025*  
*👤 Maintainer: Authentication System Team*
