<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg" alt="Donate us"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow" alt="Follow us on Twitter"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Description

Secure Authentication System built with NestJS featuring:

- 🔐 **RSA-256 JWT Authentication** with per-user asymmetric key pairs
- 🍪 **Secure Refresh Tokens** (HTTP-only cookies)
- 👥 **Role-based Access Control** (Admin, Moderator, User)
- 🚦 **Role-based Rate Limiting** (5-1000 req/min by role)
- 🔑 **Key Rotation** - Users can rotate their own RSA key pairs
- 📊 **MySQL Database** with TypeORM
- 🛡️ **Security Best Practices** - CORS, Helmet, input validation

## 🚀 Quick Start (New Machine)

### Prerequisites

- Node.js v18+
- Docker Desktop running

### One-Command Setup

**Windows PowerShell**:

```powershell
npm install && .\setup-database.ps1 && npm run start:dev
```

**Linux/Mac**:

```bash
npm install && chmod +x setup-database.sh && ./setup-database.sh && npm run start:dev
```

**Or using NPM scripts**:

```bash
npm run setup  # Install deps + setup DB + build
npm run dev    # Start Docker + dev server
```

Server will be running at: **http://localhost:3000/api**

📖 **Detailed setup guide**: See [SETUP_NEW_MACHINE.md](./SETUP_NEW_MACHINE.md)

## 📦 NPM Scripts

### Quick Commands

```bash
npm run setup      # Complete setup (install + db + build)
npm run dev        # Start Docker + dev server
npm run db:setup   # Setup database (container + schema + seed)
npm run db:reset   # Reset database completely
npm run db:check   # Verify database state
```

### Database Management

| Command               | Description           |
| --------------------- | --------------------- |
| `npm run docker:up`   | Start MySQL container |
| `npm run docker:down` | Stop MySQL container  |
| `npm run docker:logs` | View MySQL logs       |
| `npm run db:setup`    | Complete DB setup     |
| `npm run db:migrate`  | Run schema migration  |
| `npm run db:reset`    | Reset database        |

### Development

| Command             | Description           |
| ------------------- | --------------------- |
| `npm run start:dev` | Start with watch mode |
| `npm run build`     | Build TypeScript      |
| `npm test`          | Run tests             |

See [SETUP_NEW_MACHINE.md](./SETUP_NEW_MACHINE.md) for complete script reference.

### Key Features

#### 1. Asymmetric JWT Authentication

- Each user has unique RSA-2048 key pair
- Access tokens signed with private key, verified with public key
- Per-user key rotation without affecting other users
- Stored in `key_pairs` table (private key encrypted)

#### 2. Role-based Rate Limiting

| Role          | GET      | POST/PUT | Auth     | Tracking   |
| ------------- | -------- | -------- | -------- | ---------- |
| **Admin**     | 1000/min | 1000/min | 1000/min | User ID    |
| **Moderator** | 300/min  | 100/min  | 200/min  | User ID    |
| **User**      | 100/min  | 30/min   | 10/min   | User ID    |
| **Guest**     | 10/min   | 10/min   | 5-10/min | IP Address |

- Implemented with custom `RoleThrottlerGuard`
- Automatic tracking by user ID (authenticated) or IP (anonymous)
- 60-second rolling window

#### 3. Refresh Token Security

- HTTP-only cookies (XSS protection)
- Secure flag in production
- SameSite=Strict (CSRF protection)
- Stored in database with device fingerprinting
- One refresh token per device (tracked by client ID)

#### 4. Role System

- 3 predefined roles: `admin`, `moderator`, `user`
- Default role for new registrations: `user`
- Stored in separate `roles` table
- Clean API responses (roleId hidden, role object included)

### Project Structure

```
src/
├── auth/                 # Authentication module
│   ├── dto/             # Data transfer objects
│   ├── entities/        # RefreshToken, KeyPair entities
│   ├── guards/          # JwtAuthGuard
│   ├── services/        # Auth business logic
│   ├── strategies/      # JWT strategy
│   └── auth.controller.ts
├── users/               # User management
│   ├── entities/        # User entity
│   └── users.service.ts
├── roles/               # Role system (NEW)
│   ├── entities/        # Role entity
│   ├── roles.service.ts
│   └── roles.module.ts
├── common/              # Shared components
│   ├── guards/          # RoleThrottlerGuard
│   └── middleware/      # ClientIdMiddleware
├── config/              # Configuration
│   ├── database.config.ts
│   └── jwt.config.ts
└── app.module.ts        # Root module
```

### API Endpoints

#### Authentication

- `POST /api/auth/register` - Create new user (rate limit: 5/min)
- `POST /api/auth/login` - Login with email/password (rate limit: 10/min)
- `POST /api/auth/refresh` - Refresh access token (rate limit: 10/min)
- `POST /api/auth/logout` - Invalidate refresh token

#### Protected Routes (require JWT)

- `GET /api/auth/profile` - Get current user profile
- `GET /api/auth/keys` - Get user's public key
- `POST /api/auth/keys/rotate` - Rotate user's key pair (rate limit: 5/min)

### Recent Changes

#### [2025-10-17] Role-based Rate Limiting ✅

- Implemented `RoleThrottlerGuard` with dynamic rate limits
- Applied globally to all routes
- Different limits for admin, moderator, user, and guest roles
- Smart tracking: user ID (authenticated) or IP (anonymous)
- See: `RATE_LIMITING_IMPLEMENTATION.md`

#### [2025-10-16] Role Module Refactoring ✅

- Moved role system to separate module (`src/roles/`)
- Cleaner separation of concerns
- Hidden `roleId` from API responses
- Added `@Exclude()` decorator
- See: `ROLE_MODULE_REFACTORING.md`

### Documentation

- 📖 **[RATE_LIMITING_IMPLEMENTATION.md](./RATE_LIMITING_IMPLEMENTATION.md)** - Complete rate limiting guide
- 📋 **[RATE_LIMITING_QUICK_REFERENCE.md](./RATE_LIMITING_QUICK_REFERENCE.md)** - Quick reference
- 🔍 **[RATE_LIMITING_ANALYSIS.md](./RATE_LIMITING_ANALYSIS.md)** - Guard vs Middleware analysis
- 🔄 **[ROLE_MODULE_REFACTORING.md](./ROLE_MODULE_REFACTORING.md)** - Role system refactoring
- 👤 **[ROLE_SYSTEM_IMPLEMENTATION.md](./ROLE_SYSTEM_IMPLEMENTATION.md)** - Original role system docs
- 📝 **[CHANGELOG.md](./CHANGELOG.md)** - Version history

### Testing

#### Test Rate Limiting

```powershell
cd d:\authentication_test_HMD\authentication-system
.\test_rate_limit.ps1
```

Tests:

1. ✅ Guest login limiting (10 req/min)
2. ✅ Guest register limiting (5 req/min)
3. ✅ User GET requests (100 req/min)
4. ✅ User auth endpoints (10 req/min)
5. ✅ Admin high limits (1000 req/min)

#### Test Role System

```powershell
.\test_role_refactor.ps1
```

Tests:

1. ✅ roleId excluded from responses
2. ✅ role object included in responses
3. ✅ Register, login, profile endpoints

### Database Setup

#### MySQL Container

```bash
docker run --name auth_system_mysql \
  -e MYSQL_ROOT_PASSWORD=root_password \
  -e MYSQL_DATABASE=auth_system \
  -e MYSQL_USER=auth_user \
  -e MYSQL_PASSWORD=auth_password \
  -p 3306:3306 \
  -d mysql:8.0
```

#### Run Schema

```bash
mysql -h localhost -u auth_user -p auth_system < schema.sql
```

**Tables**: `users`, `roles`, `refresh_tokens`, `key_pairs`

### Environment Variables

Create `.env` file:

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=auth_user
DB_PASSWORD=auth_password
DB_DATABASE=auth_system

# JWT
JWT_SECRET=your-secret-key-here
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# App
NODE_ENV=development
PORT=3000
```

### Security Features

- ✅ RSA-256 asymmetric key pairs per user
- ✅ Refresh token rotation on use
- ✅ HTTP-only cookies for refresh tokens
- ✅ CORS configured
- ✅ Helmet for security headers
- ✅ Input validation with class-validator
- ✅ Role-based rate limiting
- ✅ IP and user tracking
- ✅ Password hashing with bcrypt
- ✅ SQL injection prevention (TypeORM)

### Production Recommendations

1. **Enable HTTPS** - Set `HTTPS=true` in production
2. **Use Redis** for rate limiting:
   ```bash
   npm install @nestjs/throttler-storage-redis ioredis
   ```
3. **Environment Variables** - Never commit `.env` file
4. **Database** - Use connection pooling
5. **Monitoring** - Set up logging and alerting
6. **Rate Limit Headers** - Add `X-RateLimit-*` headers

### Technology Stack

- **Framework**: NestJS 10.x
- **Language**: TypeScript 5.x
- **Database**: MySQL 8.0
- **ORM**: TypeORM
- **Authentication**: Passport JWT
- **Rate Limiting**: @nestjs/throttler
- **Validation**: class-validator, class-transformer
- **Security**: Helmet, CORS

### Status

- ✅ **Compilation**: 0 TypeScript errors
- ✅ **Server**: Running on http://localhost:3000/api
- ✅ **Database**: Connected to MySQL
- ✅ **Rate Limiting**: Active with role-based guards
- ✅ **Authentication**: JWT with refresh tokens working
- ✅ **Testing**: Scripts available

## Project setup

```bash
$ npm install
```

## Compile and run the project

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Run tests

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## Deployment

When you're ready to deploy your NestJS application to production, there are some key steps you can take to ensure it runs as efficiently as possible. Check out the [deployment documentation](https://docs.nestjs.com/deployment) for more information.

If you are looking for a cloud-based platform to deploy your NestJS application, check out [Mau](https://mau.nestjs.com), our official platform for deploying NestJS applications on AWS. Mau makes deployment straightforward and fast, requiring just a few simple steps:

```bash
$ npm install -g @nestjs/mau
$ mau deploy
```

With Mau, you can deploy your application in just a few clicks, allowing you to focus on building features rather than managing infrastructure.

## Resources

Check out a few resources that may come in handy when working with NestJS:

- Visit the [NestJS Documentation](https://docs.nestjs.com) to learn more about the framework.
- For questions and support, please visit our [Discord channel](https://discord.gg/G7Qnnhy).
- To dive deeper and get more hands-on experience, check out our official video [courses](https://courses.nestjs.com/).
- Deploy your application to AWS with the help of [NestJS Mau](https://mau.nestjs.com) in just a few clicks.
- Visualize your application graph and interact with the NestJS application in real-time using [NestJS Devtools](https://devtools.nestjs.com).
- Need help with your project (part-time to full-time)? Check out our official [enterprise support](https://enterprise.nestjs.com).
- To stay in the loop and get updates, follow us on [X](https://x.com/nestframework) and [LinkedIn](https://linkedin.com/company/nestjs).
- Looking for a job, or have a job to offer? Check out our official [Jobs board](https://jobs.nestjs.com).

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](https://github.com/nestjs/nest/blob/master/LICENSE).
