import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerOptions } from '@nestjs/throttler';
import { Reflector } from '@nestjs/core';

/**
 * Rate Limiting Constants
 * Centralized configuration for all rate limits
 */

// Time-to-Live (TTL) - Window duration for counting requests
const RATE_LIMIT_TTL = 60000; // 60 seconds (1 minute)

// Admin Role Rate Limits (highest privileges)
const ADMIN_RATE_LIMITS = {
  ALL: 1000, // All operations
};

// Moderator Role Rate Limits (elevated privileges)
const MODERATOR_RATE_LIMITS = {
  GET: 300, // Read operations
  WRITE: 100, // POST, PUT, PATCH operations
  DELETE: 50, // Delete operations
  DEFAULT: 200, // Fallback for other methods
};

// Regular User Role Rate Limits
const USER_RATE_LIMITS = {
  GET: 100, // Read operations
  WRITE: 30, // POST, PUT, PATCH operations
  DELETE: 20, // Delete operations
  AUTH: 10, // Login, logout, refresh operations
  EXPENSIVE: 5, // Key rotation, resource-intensive operations
  DEFAULT: 50, // Fallback for other methods
};

// Guest/Anonymous User Rate Limits (most restrictive)
const GUEST_RATE_LIMITS = {
  REGISTER: 5, // Account creation
  LOGIN: 10, // Login attempts
  DEFAULT: 10, // Other public endpoints
};

// Default fallback rate limit (when role is unknown)
const DEFAULT_RATE_LIMIT = 20;

/**
 * Role-based Rate Limiting Guard
 *
 * Rate limits based on user role:
 * - Admin: 1000 requests/min (all operations)
 * - Moderator: 50-300 requests/min (by operation type)
 * - User: 5-100 requests/min (by operation type)
 * - Guest: 5-10 requests/min (by endpoint)
 *
 * All limits use a 60-second rolling window.
 */
@Injectable()
export class RoleThrottlerGuard extends ThrottlerGuard {
  constructor(options: any, storageService: any, reflector: Reflector) {
    super(options, storageService, reflector);
  }

  /**
   * Override getThrottlerOptions to provide role-based limits
   */
  protected async getThrottlerOptions(
    context: ExecutionContext,
  ): Promise<ThrottlerOptions[]> {
    const request = context.switchToHttp().getRequest();
    const handler = context.getHandler();

    // Get user from request (set by JwtAuthGuard if authenticated)
    const user = request.user;

    // Get HTTP method
    const method = request.method;

    // Get handler name for endpoint detection
    const handlerName = handler.name;

    // Determine rate limit based on user role and endpoint
    const { limit, ttl } = this.getRateLimitForUser(user, method, handlerName);

    // Return custom throttler options for this request
    return [
      {
        limit,
        ttl,
      },
    ];
  }

  /**
   * Track requests by user ID if authenticated, otherwise by IP
   */
  protected getTracker(req: Record<string, any>): Promise<string> {
    if (req.user?.id) {
      return Promise.resolve(`user:${req.user.id}`);
    }
    return Promise.resolve(`ip:${req.ips?.length ? req.ips[0] : req.ip}`);
  }

  /**
   * Determine rate limit based on user role and request type
   */
  private getRateLimitForUser(
    user: any,
    method: string,
    handlerName: string,
  ): { limit: number; ttl: number } {
    const ttl = RATE_LIMIT_TTL;

    // Anonymous/Guest requests
    if (!user) {
      return this.getGuestRateLimit(handlerName, ttl);
    }

    // Admin role - highest limits
    if (user.role?.name === 'admin') {
      return { limit: ADMIN_RATE_LIMITS.ALL, ttl };
    }

    // Moderator role - high limits
    if (user.role?.name === 'moderator') {
      return this.getModeratorRateLimit(method, handlerName, ttl);
    }

    // Regular user role
    if (user.role?.name === 'user') {
      return this.getUserRateLimit(method, handlerName, ttl);
    }

    // Default fallback for unknown roles
    return { limit: DEFAULT_RATE_LIMIT, ttl };
  }

  /**
   * Rate limits for guest/anonymous users
   */
  private getGuestRateLimit(
    handlerName: string,
    ttl: number,
  ): { limit: number; ttl: number } {
    // Auth endpoints (login, register) - strict limits to prevent abuse
    if (handlerName === 'register') {
      return { limit: GUEST_RATE_LIMITS.REGISTER, ttl };
    }

    if (handlerName === 'login') {
      return { limit: GUEST_RATE_LIMITS.LOGIN, ttl };
    }

    // Other public endpoints
    return { limit: GUEST_RATE_LIMITS.DEFAULT, ttl };
  }

  /**
   * Rate limits for regular users
   */
  private getUserRateLimit(
    method: string,
    handlerName: string,
    ttl: number,
  ): { limit: number; ttl: number } {
    // Read operations - generous limits
    if (method === 'GET') {
      return { limit: USER_RATE_LIMITS.GET, ttl };
    }

    // Auth-related write operations - conservative for security
    if (
      handlerName === 'refresh' ||
      handlerName === 'logout' ||
      handlerName === 'login'
    ) {
      return { limit: USER_RATE_LIMITS.AUTH, ttl };
    }

    // Expensive operations (key rotation, etc.)
    if (handlerName === 'rotateKeys' || handlerName === 'register') {
      return { limit: USER_RATE_LIMITS.EXPENSIVE, ttl };
    }

    // Delete operations
    if (method === 'DELETE') {
      return { limit: USER_RATE_LIMITS.DELETE, ttl };
    }

    // Other write operations (POST, PUT, PATCH)
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      return { limit: USER_RATE_LIMITS.WRITE, ttl };
    }

    // Default for other methods
    return { limit: USER_RATE_LIMITS.DEFAULT, ttl };
  }

  /**
   * Rate limits for moderators
   */
  private getModeratorRateLimit(
    method: string,
    handlerName: string,
    ttl: number,
  ): { limit: number; ttl: number } {
    // Read operations
    if (method === 'GET') {
      return { limit: MODERATOR_RATE_LIMITS.GET, ttl };
    }

    // Write operations
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      return { limit: MODERATOR_RATE_LIMITS.WRITE, ttl };
    }

    // Delete operations
    if (method === 'DELETE') {
      return { limit: MODERATOR_RATE_LIMITS.DELETE, ttl };
    }

    // Default for other methods
    return { limit: MODERATOR_RATE_LIMITS.DEFAULT, ttl };
  }
}
