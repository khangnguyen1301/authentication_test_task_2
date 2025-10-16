import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { KeyPair } from '../entities/key-pair.entity';
import * as crypto from 'crypto';

export interface KeyPairResult {
  id: string;
  publicKey: string;
  privateKey: string;
  algorithm: string;
}

@Injectable()
export class KeyPairsService {
  private readonly logger = new Logger(KeyPairsService.name);

  constructor(
    @InjectRepository(KeyPair)
    private keyPairRepository: Repository<KeyPair>,
  ) {}

  /**
   * Generate RSA key pair (2048 bits)
   */
  private generateRSAKeyPair(): { privateKey: string; publicKey: string } {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return { privateKey, publicKey };
  }

  /**
   * Create new key pair for user
   */
  async createKeyPair(userId: string): Promise<KeyPairResult> {
    // Deactivate all existing keys for this user
    await this.deactivateAllKeys(userId);

    // Generate new RSA key pair
    const { privateKey, publicKey } = this.generateRSAKeyPair();

    // Save to database
    const keyPair = this.keyPairRepository.create({
      userId,
      privateKey,
      publicKey,
      algorithm: 'RS256',
      isActive: true,
    });

    const saved = await this.keyPairRepository.save(keyPair);

    this.logger.log(`Created new key pair for user ${userId}`);

    return {
      id: saved.id,
      publicKey: saved.publicKey,
      privateKey: saved.privateKey,
      algorithm: saved.algorithm,
    };
  }

  /**
   * Get active key pair for user
   */
  async getActiveKeyPair(userId: string): Promise<KeyPairResult | null> {
    const keyPair = await this.keyPairRepository.findOne({
      where: { userId, isActive: true },
      order: { createdAt: 'DESC' },
    });

    if (!keyPair) {
      return null;
    }

    return {
      id: keyPair.id,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      algorithm: keyPair.algorithm,
    };
  }

  /**
   * Get public key by user ID (for token verification)
   */
  async getPublicKey(userId: string): Promise<string | null> {
    const keyPair = await this.getActiveKeyPair(userId);
    return keyPair?.publicKey || null;
  }

  /**
   * Get private key by user ID (for token signing)
   */
  async getPrivateKey(userId: string): Promise<string | null> {
    const keyPair = await this.getActiveKeyPair(userId);
    return keyPair?.privateKey || null;
  }

  /**
   * Get or create key pair for user
   */
  async getOrCreateKeyPair(userId: string): Promise<KeyPairResult> {
    let keyPair = await this.getActiveKeyPair(userId);

    if (!keyPair) {
      keyPair = await this.createKeyPair(userId);
    }

    return keyPair;
  }

  /**
   * Rotate key pair (create new and deactivate old)
   */
  async rotateKeyPair(userId: string): Promise<KeyPairResult> {
    this.logger.log(`Rotating key pair for user ${userId}`);
    return this.createKeyPair(userId);
  }

  /**
   * Deactivate all keys for user
   */
  async deactivateAllKeys(userId: string): Promise<void> {
    await this.keyPairRepository.update(
      { userId, isActive: true },
      { isActive: false, revokedAt: new Date() },
    );
  }

  /**
   * Revoke specific key
   */
  async revokeKey(keyId: string, userId: string): Promise<void> {
    await this.keyPairRepository.update(
      { id: keyId, userId },
      { isActive: false, revokedAt: new Date() },
    );

    this.logger.log(`Revoked key ${keyId} for user ${userId}`);
  }

  /**
   * Get all keys for user (including inactive)
   */
  async getAllKeys(userId: string): Promise<KeyPair[]> {
    return this.keyPairRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
      select: [
        'id',
        'algorithm',
        'isActive',
        'createdAt',
        'expiresAt',
        'revokedAt',
      ],
    });
  }

  /**
   * Cleanup expired keys
   */
  async cleanupExpiredKeys(): Promise<void> {
    const result = await this.keyPairRepository
      .createQueryBuilder()
      .update()
      .set({ isActive: false, revokedAt: new Date() })
      .where('expiresAt < :now', { now: new Date() })
      .andWhere('isActive = :active', { active: true })
      .execute();

    if (result.affected && result.affected > 0) {
      this.logger.log(`Cleaned up ${result.affected} expired keys`);
    }
  }
}
