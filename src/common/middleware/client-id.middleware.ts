import {
  Injectable,
  NestMiddleware,
  BadRequestException,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

// Extend Express Request to include clientId
declare global {
  namespace Express {
    interface Request {
      clientId?: string;
    }
  }
}

@Injectable()
export class ClientIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const clientId = req.headers['x-client-id'] as string;

    // For authenticated routes, x-client-id is required
    const isAuthRoute =
      req.path.includes('/auth/profile') ||
      req.path.includes('/auth/logout') ||
      req.path.includes('/auth/refresh') ||
      req.path.includes('/auth/keys');

    if (isAuthRoute && !clientId) {
      throw new BadRequestException('x-client-id header is required');
    }

    // Attach clientId to request
    if (clientId) {
      req.clientId = clientId;
    }

    next();
  }
}
