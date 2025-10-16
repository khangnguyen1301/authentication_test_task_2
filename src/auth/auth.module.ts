import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { RolesModule } from '../roles/roles.module';
import { RefreshToken } from './entities/refresh-token.entity';
import { KeyPair } from './entities/key-pair.entity';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { KeyPairsService } from './services/key-pairs.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([RefreshToken, KeyPair]),
    UsersModule,
    RolesModule,
    PassportModule,
    JwtModule.register({}), // Configuration will be done in service
    ConfigModule,
  ],
  providers: [AuthService, JwtStrategy, JwtRefreshStrategy, KeyPairsService],
  controllers: [AuthController],
  exports: [AuthService, KeyPairsService],
})
export class AuthModule {}
