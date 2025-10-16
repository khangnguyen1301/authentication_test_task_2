-- Create Database
CREATE DATABASE IF NOT EXISTS auth_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE auth_system;

-- =====================================================
-- ROLES TABLE
-- =====================================================
-- Description: Stores system roles
-- =====================================================
CREATE TABLE IF NOT EXISTS roles (
  id VARCHAR(36) PRIMARY KEY COMMENT 'UUID',
  name VARCHAR(50) NOT NULL UNIQUE COMMENT 'Role name (e.g., admin, user, moderator)',
  description TEXT COMMENT 'Role description',
  is_active BOOLEAN DEFAULT TRUE COMMENT 'Role status',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_name (name),
  INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='System roles';

-- =====================================================
-- USERS TABLE
-- =====================================================
-- Description: Stores user accounts
-- =====================================================
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY COMMENT 'UUID',
  username VARCHAR(100) NOT NULL UNIQUE COMMENT 'Username',
  email VARCHAR(255) NOT NULL UNIQUE COMMENT 'Email address',
  password VARCHAR(255) NOT NULL COMMENT 'Hashed password',
  role_id VARCHAR(36) NOT NULL COMMENT 'Foreign key to roles',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT,
  INDEX idx_email (email),
  INDEX idx_username (username),
  INDEX idx_role_id (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User accounts';

-- =====================================================
-- REFRESH TOKENS TABLE
-- =====================================================
-- Description: Stores refresh tokens for authentication
-- =====================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id VARCHAR(36) PRIMARY KEY COMMENT 'UUID',
  user_id VARCHAR(36) NOT NULL COMMENT 'Foreign key to users',
  token TEXT NOT NULL COMMENT 'Refresh token (JWT)',
  expires_at TIMESTAMP NOT NULL COMMENT 'Token expiration',
  is_revoked BOOLEAN DEFAULT FALSE COMMENT 'Revocation status',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id),
  INDEX idx_token (token(255)),
  INDEX idx_expires_at (expires_at),
  INDEX idx_is_revoked (is_revoked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Refresh tokens';

-- =====================================================
-- KEY PAIRS TABLE
-- =====================================================
-- Description: Stores RSA key pairs for asymmetric JWT signing
-- =====================================================
CREATE TABLE IF NOT EXISTS key_pairs (
  id VARCHAR(36) PRIMARY KEY COMMENT 'UUID',
  userId VARCHAR(36) NOT NULL COMMENT 'Foreign key to users',
  privateKey TEXT NOT NULL COMMENT 'RSA private key (PEM format)',
  publicKey TEXT NOT NULL COMMENT 'RSA public key (PEM format)',
  algorithm VARCHAR(20) DEFAULT 'RS256' COMMENT 'Algorithm (RS256, RS384, RS512)',
  isActive BOOLEAN DEFAULT TRUE COMMENT 'Key pair status',
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expiresAt TIMESTAMP NULL COMMENT 'Key expiration (NULL = no expiration)',
  revokedAt TIMESTAMP NULL COMMENT 'Revocation timestamp',
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_userId (userId),
  INDEX idx_isActive (isActive),
  INDEX idx_userId_isActive (userId, isActive),
  INDEX idx_expiresAt (expiresAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='RSA key pairs for JWT';

-- =====================================================
-- SEED DATA
-- =====================================================

-- Insert default roles
INSERT INTO roles (id, name, description, is_active) VALUES
  (UUID(), 'admin', 'Administrator with full system access', TRUE),
  (UUID(), 'user', 'Standard user with basic access', TRUE),
  (UUID(), 'moderator', 'Moderator with content management access', TRUE)
ON DUPLICATE KEY UPDATE name=name;
