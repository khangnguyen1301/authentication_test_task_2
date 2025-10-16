import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { User, UserRole } from '../users/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { KeyPairsService } from './services/key-pairs.service';
import { RolesService } from '../roles/roles.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly keyPairsService: KeyPairsService,
    private readonly rolesService: RolesService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
  ) {}

  async register(registerDto: RegisterDto) {
    const { username, email, password, role } = registerDto;

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Get role ID - use default 'user' role if not specified
    let roleId: string;
    if (role) {
      // If role is specified, try to find it
      try {
        const roleEntity = await this.rolesService.findByName(role);
        roleId = roleEntity.id;
      } catch (error) {
        // If role not found, use default
        const defaultRole = await this.rolesService.getDefaultRole();
        roleId = defaultRole.id;
      }
    } else {
      // Use default 'user' role
      const defaultRole = await this.rolesService.getDefaultRole();
      roleId = defaultRole.id;
    }

    // Create user with roleId
    const user = await this.usersService.create(
      username,
      email,
      hashedPassword,
      roleId,
    );

    // Generate RSA key pair for this user
    await this.keyPairsService.createKeyPair(user.id);

    // Remove password from response
    const { password: _, ...result } = user;
    return result;
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    // Validate user
    const user = await this.validateUser(email, password);

    // Ensure user has key pair (create if not exists)
    await this.keyPairsService.getOrCreateKeyPair(user.id);

    // Generate tokens
    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user);

    // Save refresh token to database
    await this.saveRefreshToken(user.id, refreshToken);

    const { password: _, ...userWithoutPassword } = user;

    return {
      accessToken,
      refreshToken,
      expiresIn: parseInt(this.configService.get('jwt.expiresIn') || '3600'),
      user: userWithoutPassword,
    };
  }

  async refreshTokens(userId: string, refreshToken: string) {
    console.log('🚀 ~ AuthService ~ refreshTokens ~ userId:', userId);
    try {
      const privateKey = await this.keyPairsService.getPrivateKey(userId);

      if (!privateKey) {
        throw new UnauthorizedException('User key pair not found');
      }
      // Verify refresh token
      const isValid = await this.jwtService.verifyAsync(refreshToken, {
        secret: privateKey,
      });
      if (!isValid) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      // Check if token exists in database and not revoked
      const storedToken = await this.refreshTokenRepository.findOne({
        where: { token: refreshToken, isRevoked: false },
        relations: ['user'],
      });

      if (!storedToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Check if token is expired
      if (storedToken.expiresAt < new Date()) {
        throw new UnauthorizedException('Refresh token expired');
      }

      const user = storedToken.user;

      // Generate new tokens
      const newAccessToken = await this.generateAccessToken(user);
      const newRefreshToken = await this.generateRefreshToken(user);

      // Revoke old refresh token
      storedToken.isRevoked = true;
      await this.refreshTokenRepository.save(storedToken);

      // Save new refresh token
      await this.saveRefreshToken(user.id, newRefreshToken);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: parseInt(this.configService.get('jwt.expiresIn') || '3600'),
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(userId: string, refreshToken: string) {
    // Revoke refresh token
    const token = await this.refreshTokenRepository.findOne({
      where: { token: refreshToken, userId, isRevoked: false },
    });

    if (token) {
      token.isRevoked = true;
      await this.refreshTokenRepository.save(token);
    }

    // Optional: Revoke all keys for maximum security
    // This will invalidate ALL tokens (access + refresh) immediately
    await this.keyPairsService.deactivateAllKeys(userId);
    return {
      message: 'Đăng xuất thành công và đã revoke tất cả keys',
      keysRevoked: true,
      warning: 'Tất cả tokens đã bị vô hiệu hóa. Vui lòng đăng nhập lại.',
    };
  }

  async validateUser(email: string, password: string): Promise<User> {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.comparePassword(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return user;
  }

  async hashPassword(password: string): Promise<string> {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
  }

  async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }

  async generateAccessToken(user: User): Promise<string> {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role?.name || 'user', // Use role name from relation
    };

    // Get user's private key for signing (NOT public key!)
    const privateKey = await this.keyPairsService.getPrivateKey(user.id);

    if (!privateKey) {
      throw new UnauthorizedException('User key pair not found');
    }

    return await this.jwtService.signAsync(payload, {
      privateKey: privateKey,
      algorithm: 'RS256',
      expiresIn: `${this.configService.get('jwt.expiresIn')}s`,
    });
  }

  async generateRefreshToken(user: User): Promise<string> {
    const payload = {
      sub: user.id,
      email: user.email,
      type: 'refresh',
    };

    // Get user's private key for signing
    const privateKey = await this.keyPairsService.getPrivateKey(user.id);

    if (!privateKey) {
      throw new UnauthorizedException('User key pair not found');
    }

    return await this.jwtService.signAsync(payload, {
      privateKey,
      algorithm: 'RS256',
      expiresIn: `${this.configService.get('jwt.refreshExpiresIn')}s`,
    });
  }

  async saveRefreshToken(userId: string, token: string): Promise<void> {
    const expiresIn = parseInt(
      this.configService.get('jwt.refreshExpiresIn') || '604800',
    );
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + expiresIn);

    const refreshToken = this.refreshTokenRepository.create({
      userId,
      token,
      expiresAt,
    });

    await this.refreshTokenRepository.save(refreshToken);
  }

  // Cleanup expired tokens (should be called by a scheduled task)
  async cleanupExpiredTokens(): Promise<void> {
    await this.refreshTokenRepository.delete({
      expiresAt: LessThan(new Date()),
    });
  }
}
