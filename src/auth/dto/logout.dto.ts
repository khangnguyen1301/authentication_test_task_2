import { IsNotEmpty, IsString, IsBoolean, IsOptional } from 'class-validator';

export class LogoutDto {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;

  @IsBoolean()
  @IsOptional()
  revokeKeys?: boolean; // Optional: Revoke all keys for secure logout
}
