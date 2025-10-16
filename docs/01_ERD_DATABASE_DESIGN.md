# Entity Relationship Diagram (ERD) - Authentication System

## 📊 Tổng Quan Database

Hệ thống Authentication sử dụng 4 bảng chính với các mối quan hệ được thiết kế để hỗ trợ xác thực người dùng với JWT và mã hóa bất đối xứng RSA.

---

## 🗂️ Database Schema

### Database: `auth_system`
- **Character Set**: utf8mb4
- **Collation**: utf8mb4_unicode_ci

---

## 📋 Các Bảng Chính

### 1. **roles** (Quản lý vai trò)

Lưu trữ các vai trò trong hệ thống.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID của vai trò |
| `name` | VARCHAR(50) | NOT NULL, UNIQUE | Tên vai trò (admin, user, moderator) |
| `description` | TEXT | NULL | Mô tả vai trò |
| `is_active` | BOOLEAN | DEFAULT TRUE | Trạng thái vai trò |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Thời gian tạo |
| `updated_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP ON UPDATE | Thời gian cập nhật |

**Indexes:**
- `idx_name` - Index trên cột name
- `idx_is_active` - Index trên cột is_active

**Dữ liệu mặc định:**
- admin: Quản trị viên có toàn quyền
- user: Người dùng tiêu chuẩn
- moderator: Người kiểm duyát nội dung

---

### 2. **users** (Quản lý người dùng)

Lưu trữ thông tin tài khoản người dùng.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID của người dùng |
| `username` | VARCHAR(100) | NOT NULL, UNIQUE | Tên đăng nhập |
| `email` | VARCHAR(255) | NOT NULL, UNIQUE | Email |
| `password` | VARCHAR(255) | NOT NULL | Password đã hash (bcrypt) |
| `role_id` | VARCHAR(36) | NOT NULL, FK → roles(id) | Vai trò của user |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Thời gian tạo |
| `updated_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP ON UPDATE | Thời gian cập nhật |

**Indexes:**
- `idx_email` - Index trên email
- `idx_username` - Index trên username
- `idx_role_id` - Index trên role_id

**Foreign Keys:**
- `role_id` → `roles(id)` ON DELETE RESTRICT

**Quan hệ:**
- **ManyToOne** với `roles`: Một user thuộc một vai trò
- **OneToMany** với `refresh_tokens`: Một user có nhiều refresh tokens
- **OneToMany** với `key_pairs`: Một user có nhiều key pairs

---

### 3. **refresh_tokens** (Quản lý Refresh Tokens)

Lưu trữ các refresh token để làm mới access token.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID của token |
| `user_id` | VARCHAR(36) | NOT NULL, FK → users(id) | ID người dùng |
| `token` | TEXT | NOT NULL | JWT refresh token |
| `expires_at` | TIMESTAMP | NOT NULL | Thời điểm hết hạn |
| `is_revoked` | BOOLEAN | DEFAULT FALSE | Token đã bị thu hồi |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Thời gian tạo |

**Indexes:**
- `idx_user_id` - Index trên user_id
- `idx_token` - Index trên 255 ký tự đầu của token
- `idx_expires_at` - Index trên expires_at
- `idx_is_revoked` - Index trên is_revoked

**Foreign Keys:**
- `user_id` → `users(id)` ON DELETE CASCADE

**Quan hệ:**
- **ManyToOne** với `users`: Nhiều tokens thuộc một user

**Đặc điểm:**
- Refresh token có thời gian sống dài (7 ngày)
- Có thể bị revoke khi logout
- Token cũ sẽ bị revoke khi tạo token mới

---

### 4. **key_pairs** (Quản lý Cặp Khóa RSA)

Lưu trữ các cặp khóa RSA cho JWT asymmetric signing.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID của key pair |
| `userId` | VARCHAR(36) | NOT NULL, FK → users(id) | ID người dùng |
| `privateKey` | TEXT | NOT NULL | RSA private key (PEM format) |
| `publicKey` | TEXT | NOT NULL | RSA public key (PEM format) |
| `algorithm` | VARCHAR(20) | DEFAULT 'RS256' | Thuật toán (RS256, RS384, RS512) |
| `isActive` | BOOLEAN | DEFAULT TRUE | Trạng thái key pair |
| `createdAt` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Thời gian tạo |
| `expiresAt` | TIMESTAMP | NULL | Thời điểm hết hạn (NULL = không hết hạn) |
| `revokedAt` | TIMESTAMP | NULL | Thời điểm thu hồi |

**Indexes:**
- `idx_userId` - Index trên userId
- `idx_isActive` - Index trên isActive
- `idx_userId_isActive` - Composite index
- `idx_expiresAt` - Index trên expiresAt

**Foreign Keys:**
- `userId` → `users(id)` ON DELETE CASCADE

**Quan hệ:**
- **ManyToOne** với `users`: Nhiều key pairs thuộc một user

**Đặc điểm:**
- Mỗi user có thể có nhiều key pairs nhưng chỉ 1 active
- Private key dùng để ký JWT
- Public key dùng để verify JWT
- Key rotation: Tạo key mới sẽ deactivate key cũ
- RSA 2048 bits

---

## 🔗 Entity Relationship Diagram

```
┌─────────────────┐
│     roles       │
│─────────────────│
│ id (PK)         │
│ name (UK)       │
│ description     │
│ is_active       │
│ created_at      │
│ updated_at      │
└────────┬────────┘
         │
         │ 1
         │
         │ N
         │
┌────────┴────────────────┐
│        users            │
│─────────────────────────│
│ id (PK)                 │
│ username (UK)           │
│ email (UK)              │
│ password                │
│ role_id (FK)            │◄────────┐
│ created_at              │         │
│ updated_at              │         │
└────────┬────────────────┘         │
         │                           │
         │ 1                         │
         │                           │
    ┌────┴──────────┐                │
    │               │                │
    │ N             │ N              │
    │               │                │
┌───┴───────────┐   │          ┌─────┴───────────┐
│refresh_tokens │   │          │   key_pairs     │
│───────────────│   │          │─────────────────│
│ id (PK)       │   │          │ id (PK)         │
│ user_id (FK)  │───┘          │ userId (FK)     │
│ token         │              │ privateKey      │
│ expires_at    │              │ publicKey       │
│ is_revoked    │              │ algorithm       │
│ created_at    │              │ isActive        │
└───────────────┘              │ createdAt       │
                               │ expiresAt       │
                               │ revokedAt       │
                               └─────────────────┘
```

---

## 📐 Mô Tả Quan Hệ

### 1. **roles ↔ users** (One-to-Many)
- **Quan hệ**: 1 role có nhiều users
- **Khóa ngoại**: `users.role_id` → `roles.id`
- **Cascade**: ON DELETE RESTRICT (không cho xóa role nếu còn user)
- **Ý nghĩa**: Mỗi user chỉ có 1 vai trò, nhưng nhiều user có thể cùng vai trò

### 2. **users ↔ refresh_tokens** (One-to-Many)
- **Quan hệ**: 1 user có nhiều refresh tokens
- **Khóa ngoại**: `refresh_tokens.user_id` → `users.id`
- **Cascade**: ON DELETE CASCADE (xóa user → xóa tất cả tokens)
- **Ý nghĩa**: User có thể đăng nhập từ nhiều thiết bị, mỗi thiết bị có 1 refresh token

### 3. **users ↔ key_pairs** (One-to-Many)
- **Quan hệ**: 1 user có nhiều key pairs (nhưng chỉ 1 active)
- **Khóa ngoại**: `key_pairs.userId` → `users.id`
- **Cascade**: ON DELETE CASCADE (xóa user → xóa tất cả keys)
- **Ý nghĩa**: Hỗ trợ key rotation và lịch sử keys

---

## 🔐 Bảo Mật Database

### 1. **Password Storage**
- Hash bằng bcrypt (salt rounds: 10)
- Không bao giờ lưu plain text password

### 2. **Token Storage**
- Refresh tokens được lưu trong database để có thể revoke
- Access tokens KHÔNG lưu trong database (stateless)
- Index trên token để tra cứu nhanh

### 3. **Key Pair Management**
- Private keys được lưu an toàn trong database
- Chỉ service backend mới access được private key
- Public key có thể chia sẻ cho verification

### 4. **Cascade Deletion**
- Xóa user → tự động xóa tokens và keys
- Không cho xóa role nếu còn user

---

## 📊 Indexes và Performance

### Indexes được tối ưu cho:

1. **Lookup nhanh user:**
   - `users.email` (unique)
   - `users.username` (unique)

2. **Authorization:**
   - `users.role_id`
   - `roles.name`

3. **Token management:**
   - `refresh_tokens.user_id`
   - `refresh_tokens.token` (partial index 255 chars)
   - `refresh_tokens.is_revoked`
   - `refresh_tokens.expires_at`

4. **Key management:**
   - `key_pairs.userId`
   - `key_pairs.isActive`
   - Composite: `(userId, isActive)`

---

## 🧹 Data Cleanup

### Scheduled Tasks:

1. **Cleanup expired refresh tokens:**
   ```sql
   DELETE FROM refresh_tokens 
   WHERE expires_at < NOW();
   ```

2. **Cleanup expired key pairs:**
   ```sql
   UPDATE key_pairs 
   SET isActive = FALSE, revokedAt = NOW()
   WHERE expiresAt < NOW() AND isActive = TRUE;
   ```

---

## 📈 Database Statistics

### Ước tính kích thước:

| Table | Columns Size | Indexes | Estimate per Row |
|-------|--------------|---------|------------------|
| roles | ~200 bytes | ~100 bytes | ~300 bytes |
| users | ~600 bytes | ~200 bytes | ~800 bytes |
| refresh_tokens | ~500 bytes | ~300 bytes | ~800 bytes |
| key_pairs | ~3KB | ~200 bytes | ~3.2 KB |

**Ví dụ:** 10,000 users với 2 active sessions mỗi user:
- users: 10,000 × 800 bytes ≈ 8 MB
- refresh_tokens: 20,000 × 800 bytes ≈ 16 MB
- key_pairs: 10,000 × 3.2 KB ≈ 32 MB
- **Total**: ~56 MB (chưa tính overhead)

---

## 🎯 Best Practices

1. ✅ Sử dụng UUID cho primary keys (bảo mật hơn auto-increment)
2. ✅ Index các cột thường xuyên query
3. ✅ Cascade delete để maintain referential integrity
4. ✅ Timestamp tracking cho audit trail
5. ✅ Boolean flags cho soft delete/revoke
6. ✅ TEXT type cho keys và tokens (flexible size)
7. ✅ UTF8MB4 để hỗ trợ emoji và unicode
8. ✅ Scheduled cleanup cho expired data

---

## 🔄 Key Rotation Strategy

```
User Login (Day 0)
    ↓
Create Key Pair #1 (isActive = true)
    ↓
Generate JWT signed with Private Key #1
    ↓
[After 30 days or security event]
    ↓
Create Key Pair #2 (isActive = true)
    ↓
Key Pair #1 (isActive = false, revokedAt = NOW)
    ↓
New JWT signed with Private Key #2
    ↓
Old tokens become invalid
```

---

*📝 Document Version: 1.0*  
*📅 Last Updated: October 17, 2025*  
*👤 Author: Authentication System Team*
