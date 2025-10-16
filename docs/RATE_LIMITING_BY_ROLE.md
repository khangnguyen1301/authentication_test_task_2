# 🚦 Rate Limiting Based on User Roles

## 📋 Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Cách Hoạt Động](#cách-hoạt-động)

---

## 🎯 Tổng Quan

Hệ thống authentication sử dụng **Role-based Rate Limiting** để kiểm soát số lượng request từ users dựa trên vai trò của họ.

### ✨ Key Features

- ✅ **Dynamic Rate Limits** - Khác nhau cho từng role
- ✅ **Smart Tracking** - Theo User ID (authenticated) hoặc IP (guest)
- ✅ **60-Second Window** - Rolling time window
- ✅ **Automatic Enforcement** - Áp dụng tự động cho tất cả endpoints
- ✅ **Flexible Configuration** - Dễ dàng customize

---

## 📊 Rate Limit Configuration

### Current Rate Limits

| **Route**            | **Phương thức** | **Rate Limit (requests/phút)**              | **Đối tượng áp dụng**   | **Lý do / Giải thích chi tiết**                                                                                                                                                            |
| -------------------- | --------------- | ------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/api/auth/register` | `POST`          | **5/phút**                                  | Tất cả người dùng       | Đăng ký tài khoản mới là hành động nhạy cảm, dễ bị **spam tạo account ảo**. Giới hạn thấp để **ngăn brute-force và abuse**.                                                                |
| `/api/auth/login`    | `POST`          | **10/phút**                                 | Tất cả người dùng       | Dễ bị tấn công **brute-force password**. Giới hạn 10 để bảo vệ tài khoản, nhưng vẫn đủ cho trường hợp người dùng nhập sai vài lần.                                                         |
| `/api/auth/refresh`  | `POST`          | **30/phút**                                 | Người dùng đã đăng nhập | Refresh token thường được dùng tự động (silent refresh). Giới hạn cao hơn vì hành động này **ít rủi ro**, chủ yếu để **bảo vệ hệ thống tránh spam API**.                                   |
| `/api/auth/logout`   | `POST`          | **20/phút**                                 | Người dùng đã đăng nhập | Logout không gây hại nhiều, nhưng vẫn nên giới hạn để **ngăn request liên tục gây tải hệ thống hoặc log spam**.                                                                            |
| `/api/auth/profile`  | `GET`           | **60/phút (user)**<br>**1000/phút (admin)** | Người dùng / Admin      | Profile là request đọc dữ liệu, có thể được gọi thường xuyên bởi client hoặc dashboard. Với admin, giới hạn cao hơn vì họ có thể cần **truy cập dữ liệu của nhiều người dùng** để quản lý. |

### Breakdown by Endpoint Type

#### 1. Authentication Endpoints (Login, Register, Refresh)

```typescript
{
  ttl: 60000,        // 60 seconds
  limit: {
    admin: 1000,     // Unlimited cho admin
    moderator: 200,  // 200 requests/min
    user: 10,        // 10 requests/min
    default: 5       // 5 requests/min cho guest
  }
}
```

**Áp dụng cho:**

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`

**Lý do:**

- Login/register là sensitive operations
- Ngăn chặn brute force attacks
- Guest có limit thấp nhất (5/min)

---

#### 2. GET Endpoints (Read Operations)

```typescript
{
  ttl: 60000,        // 60 seconds
  limit: {
    admin: 1000,     // 1000 requests/min
    moderator: 300,  // 300 requests/min
    user: 100,       // 100 requests/min
    default: 10      // 10 requests/min cho guest
  }
}
```

**Áp dụng cho:**

- `GET /auth/profile`
- `GET /auth/keys`
- Tất cả GET endpoints khác

**Lý do:**

- Read operations ít resource-intensive hơn
- Cho phép higher limits
- Admin có unlimited access

---

#### 3. POST/PUT Endpoints (Write Operations)

```typescript
{
  ttl: 60000,        // 60 seconds
  limit: {
    admin: 1000,     // 1000 requests/min
    moderator: 100,  // 100 requests/min
    user: 30,        // 30 requests/min
    default: 10      // 10 requests/min cho guest
  }
}
```

**Áp dụng cho:**

- `POST /users/create`
- `PUT /users/update`
- `DELETE /users/delete`

**Lý do:**

- Write operations resource-intensive
- Cần kiểm soát chặt chẽ hơn
- Ngăn spam và abuse

---

## 🔧 Cách Hoạt Động

### Flow Diagram

```
┌─────────────────┐
│  Request đến    │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│ RoleThrottlerGuard kích hoạt│
└────────┬────────────────────┘
         │
         ▼
┌────────────────────────────────┐
│ Check: User authenticated?      │
└────┬───────────────────────┬───┘
     │ YES                   │ NO
     ▼                       ▼
┌─────────────────┐    ┌──────────────┐
│ Get User Role   │    │ Role = guest │
│ from request    │    │ Track by IP  │
└────────┬────────┘    └──────┬───────┘
         │                    │
         └────────┬───────────┘
                  ▼
         ┌──────────────────┐
         │ Determine Limit  │
         │ based on Role    │
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────────┐
         │ Check Request Count  │
         │ in 60-second window  │
         └────────┬─────────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
   Count <= Limit      Count > Limit
        │                   │
        ▼                   ▼
   ✅ Allow          ❌ Block (429)
```
