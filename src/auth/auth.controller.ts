import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  Res,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LogoutDto } from './dto/logout.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { UserRole } from '../users/entities/user.entity';
import { KeyPairsService } from './services/key-pairs.service';
import { RoleThrottlerGuard } from 'src/common/guards/role-throttler.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly keyPairsService: KeyPairsService,
  ) {}

  @Post('register')
  @UseGuards(RoleThrottlerGuard)
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto) {
    const user = await this.authService.register(registerDto);
    return {
      statusCode: HttpStatus.CREATED,
      message: 'Đăng ký thành công',
      data: user,
    };
  }

  @Post('login')
  @UseGuards(RoleThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(loginDto);

    // Set refresh token in HTTP-only cookie
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true, // Prevents JavaScript access (XSS protection)
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // CSRF protection
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      path: '/', // Cookie available for all routes
    });

    // Remove refresh token from response body
    const { refreshToken, ...dataWithoutRefreshToken } = result;
    const {
      user: { roleId, ...restUser },
    } = dataWithoutRefreshToken;
    return {
      statusCode: HttpStatus.OK,
      message: 'Đăng nhập thành công',
      data: { ...dataWithoutRefreshToken, user: { ...restUser } },
    };
  }

  @Post('refresh')
  @UseGuards(JwtAuthGuard, RoleThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  async refresh(
    @CurrentUser() user: any,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    console.log('🚀 ~ AuthController ~ refresh ~ user:', user);
    // Get refresh token from cookie
    const refreshToken = req.cookies?.refreshToken;
    console.log('🚀 ~ AuthController ~ refresh ~ refreshToken:', refreshToken);

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found in cookie');
    }

    const result = await this.authService.refreshTokens(user.id, refreshToken);

    // Update refresh token cookie with new token
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    // Remove refresh token from response body
    const { refreshToken: _, ...dataWithoutRefreshToken } = result;

    return {
      statusCode: HttpStatus.OK,
      message: 'Token được làm mới thành công',
      data: dataWithoutRefreshToken,
    };
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard, RoleThrottlerGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @CurrentUser() user: any,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Get refresh token from cookie
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found in cookie');
    }

    const result = await this.authService.logout(user.id, refreshToken);

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });

    return {
      statusCode: HttpStatus.OK,
      ...result,
    };
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard, RolesGuard, RoleThrottlerGuard)
  async getProfile(@CurrentUser() user: any) {
    // Check if user is admin to determine canEdit
    const canEdit = user.role.name === UserRole.ADMIN;

    return {
      statusCode: HttpStatus.OK,
      data: {
        ...user,
        canEdit,
      },
    };
  }

  // Key Management Endpoints

  @Get('keys')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getKeys(@CurrentUser() user: any) {
    const keys = await this.keyPairsService.getAllKeys(user.id);
    return {
      statusCode: HttpStatus.OK,
      message: 'Danh sách key pairs',
      data: keys,
    };
  }
}
