import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { KeyPairsService } from '../services/key-pairs.service';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
    private readonly keyPairsService: KeyPairsService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: async (
        request: Request,
        rawJwtToken: any,
        done: any,
      ) => {
        try {
          // Extract x-client-id from request headers
          const clientId = request.headers['x-client-id'] as string;

          if (!clientId) {
            return done(
              new UnauthorizedException('x-client-id header is required'),
              null,
            );
          }

          // Get public key for this user
          const publicKey = await this.keyPairsService.getPublicKey(clientId);
          console.log('🚀 ~ JwtStrategy ~ constructor ~ publicKey:', publicKey);

          if (!publicKey) {
            return done(
              new UnauthorizedException('Invalid client ID or key not found'),
              null,
            );
          }

          done(null, publicKey);
        } catch (error) {
          done(error, null);
        }
      },
      algorithms: ['RS256'],
      passReqToCallback: false,
    });
  }

  async validate(payload: any) {
    const user = await this.usersService.findById(payload.sub);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // CRITICAL: Check if the key pair is still active
    // This prevents using tokens after key revocation (e.g., after secure logout)
    const activeKeyPair = await this.keyPairsService.getActiveKeyPair(user.id);

    if (!activeKeyPair) {
      throw new UnauthorizedException(
        'Key pair has been revoked. Please login again.',
      );
    }

    // Return user object which will be attached to request
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    };
  }
}
