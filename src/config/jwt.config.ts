import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  // For backward compatibility (fallback to symmetric if no keys)
  expiresIn: process.env.JWT_EXPIRATION || '3600',
  refreshExpiresIn: process.env.JWT_REFRESH_EXPIRATION || '604800',

  // Asymmetric JWT configuration
  algorithm: 'RS256', // RSA with SHA-256
  // Keys are now stored per-user in database
  // Use KeyPairsService to get private/public keys
}));
