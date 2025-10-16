import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from './entities/role.entity';

@Injectable()
export class RolesService {
  constructor(
    @InjectRepository(Role)
    private rolesRepository: Repository<Role>,
  ) {}

  /**
   * Find all roles
   */
  async findAll(): Promise<Role[]> {
    return this.rolesRepository.find({
      where: { isActive: true },
      order: { name: 'ASC' },
    });
  }

  /**
   * Find role by ID
   */
  async findById(id: string): Promise<Role> {
    const role = await this.rolesRepository.findOne({
      where: { id },
    });

    if (!role) {
      throw new NotFoundException(`Role with ID ${id} not found`);
    }

    return role;
  }

  /**
   * Find role by name
   */
  async findByName(name: string): Promise<Role> {
    const role = await this.rolesRepository.findOne({
      where: { name },
    });

    if (!role) {
      throw new NotFoundException(`Role with name ${name} not found`);
    }

    return role;
  }

  /**
   * Get default user role
   */
  async getDefaultRole(): Promise<Role> {
    return this.findByName('user');
  }

  /**
   * Get admin role
   */
  async getAdminRole(): Promise<Role> {
    return this.findByName('admin');
  }

  /**
   * Check if role exists by name
   */
  async existsByName(name: string): Promise<boolean> {
    const count = await this.rolesRepository.count({
      where: { name },
    });
    return count > 0;
  }

  /**
   * Create new role
   */
  async create(name: string, description?: string): Promise<Role> {
    const role = this.rolesRepository.create({
      name,
      description,
      isActive: true,
    });

    return this.rolesRepository.save(role);
  }

  /**
   * Update role
   */
  async update(
    id: string,
    data: { name?: string; description?: string; isActive?: boolean },
  ): Promise<Role> {
    const role = await this.findById(id);

    Object.assign(role, data);

    return this.rolesRepository.save(role);
  }

  /**
   * Delete role (soft delete by setting isActive to false)
   */
  async delete(id: string): Promise<void> {
    const role = await this.findById(id);

    // Prevent deleting system roles
    if (role.name === 'admin' || role.name === 'user') {
      throw new Error('Cannot delete system roles');
    }

    role.isActive = false;
    await this.rolesRepository.save(role);
  }
}
