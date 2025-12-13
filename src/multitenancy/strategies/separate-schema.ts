/**
 * Separate Schema Tenant Strategy
 * 
 * Each tenant has its own schema within the same database.
 * This provides better isolation than shared schema while still maintaining a single database.
 * 
 * Pros:
 * - Better data isolation than shared schema
 * - Easier tenant-specific backups
 * - Tenant-specific schema customization
 * 
 * Cons:
 * - More complex to implement
 * - Schema management overhead
 * - Database connection management
 */

import { Request } from 'express';
import { PrismaClient } from '@prisma/client';
import { TenantContext } from '../../core/types';
import { TenantStrategy } from '../manager';

export interface SeparateSchemaConfig {
  databaseUrl: string;
  schemaPrefix?: string;
  maxConnections?: number;
  cacheTtl?: number;
}

export class SeparateSchemaStrategy implements TenantStrategy {
  public readonly name = 'separate_schema';
  private databaseUrl: string;
  private schemaPrefix: string;
  private maxConnections: number;
  private cacheTtl: number;
  private tenantCache: Map<string, TenantContext> = new Map();
  private prismaClients: Map<string, PrismaClient> = new Map();
  private masterClient: PrismaClient;

  constructor(config: SeparateSchemaConfig) {
    this.databaseUrl = config.databaseUrl;
    this.schemaPrefix = config.schemaPrefix || 'tenant_';
    this.maxConnections = config.maxConnections || 10;
    this.cacheTtl = config.cacheTtl || 5 * 60 * 1000; // 5 minutes default

    // Master client for tenant management (uses public schema)
    this.masterClient = new PrismaClient({
      datasources: {
        db: {
          url: this.databaseUrl,
        },
      },
    });
  }

  /**
   * Get Prisma client for specific tenant schema
   */
  public async getPrismaClient(tenantId: string): Promise<PrismaClient> {
    // Check if client already exists in cache
    if (this.prismaClients.has(tenantId)) {
      return this.prismaClients.get(tenantId)!;
    }

    // Validate tenant exists
    const isValid = await this.validateTenant(tenantId);
    if (!isValid) {
      throw new Error(`Invalid tenant: ${tenantId}`);
    }

    // Get schema name for tenant
    const schemaName = this.getSchemaName(tenantId);

    // Create new Prisma client with schema override
    const client = new PrismaClient({
      datasources: {
        db: {
          url: this.getDatabaseUrlWithSchema(schemaName),
        },
      },
    });

    // Cache the client
    this.prismaClients.set(tenantId, client);

    // Implement connection pool limit
    if (this.prismaClients.size > this.maxConnections) {
      await this.evictOldestClient();
    }

    return client;
  }

  /**
   * Resolve tenant ID from request
   */
  public async resolveTenantId(request: Request): Promise<string | null> {
    // Try to get from URL params (e.g., /api/tenants/:tenantId/...)
    if (request.params.tenantId) {
      return request.params.tenantId;
    }

    // Try to get from query params
    if (request.query.tenantId && typeof request.query.tenantId === 'string') {
      return request.query.tenantId;
    }

    // Try to get from user context (if authenticated)
    const user = (request as any).user;
    if (user && user.tenant_id) {
      return user.tenant_id;
    }

    return null;
  }

  /**
   * Validate if tenant exists and is active
   */
  public async validateTenant(tenantId: string): Promise<boolean> {
    try {
      const tenant = await (this.masterClient as any).tenant.findUnique({
        where: { id: tenantId },
        select: { id: true, isActive: true },
      });

      return tenant && tenant.isActive;
    } catch (error) {
      console.error(`Error validating tenant ${tenantId}:`, error);
      return false;
    }
  }

  /**
   * Get tenant context
   */
  public async getTenantContext(tenantId: string): Promise<TenantContext | null> {
    // Check cache first
    const cached = this.tenantCache.get(tenantId);
    if (cached) {
      return cached;
    }

    try {
      const tenant = await (this.masterClient as any).tenant.findUnique({
        where: { id: tenantId },
        select: {
          id: true,
          name: true,
          config: true,
          isActive: true,
        },
      });

      if (!tenant || !tenant.isActive) {
        return null;
      }

      const schemaName = this.getSchemaName(tenantId);

      const context: TenantContext = {
        id: tenant.id,
        name: tenant.name,
        config: tenant.config || {},
        schema: schemaName,
      };

      // Cache the context
      this.tenantCache.set(tenantId, context);

      // Set up cache expiry
      setTimeout(() => {
        this.tenantCache.delete(tenantId);
      }, this.cacheTtl);

      return context;
    } catch (error) {
      console.error(`Error fetching tenant context for ${tenantId}:`, error);
      return null;
    }
  }

  /**
   * Get schema name for tenant
   */
  private getSchemaName(tenantId: string): string {
    return `${this.schemaPrefix}${tenantId}`;
  }

  /**
   * Get database URL with schema
   */
  private getDatabaseUrlWithSchema(schemaName: string): string {
    const url = new URL(this.databaseUrl);
    url.searchParams.set('schema', schemaName);
    return url.toString();
  }

  /**
   * Evict oldest client when connection pool is full
   */
  private async evictOldestClient(): Promise<void> {
    const firstKey = this.prismaClients.keys().next().value;
    if (firstKey) {
      const client = this.prismaClients.get(firstKey);
      if (client) {
        await client.$disconnect();
        this.prismaClients.delete(firstKey);
      }
    }
  }

  /**
   * Create schema for new tenant
   */
  public async createTenantSchema(tenantId: string): Promise<boolean> {
    try {
      const schemaName = this.getSchemaName(tenantId);
      
      // Create schema in database
      await this.masterClient.$executeRawUnsafe(
        `CREATE SCHEMA IF NOT EXISTS "${schemaName}"`
      );

      // Run migrations for the new schema
      // Note: You'll need to implement migration logic here
      // This typically involves running Prisma migrations against the new schema

      return true;
    } catch (error) {
      console.error(`Error creating schema for tenant ${tenantId}:`, error);
      return false;
    }
  }

  /**
   * Drop schema for tenant (use with caution!)
   */
  public async dropTenantSchema(tenantId: string): Promise<boolean> {
    try {
      const schemaName = this.getSchemaName(tenantId);
      
      // Disconnect client if exists
      const client = this.prismaClients.get(tenantId);
      if (client) {
        await client.$disconnect();
        this.prismaClients.delete(tenantId);
      }

      // Drop schema
      await this.masterClient.$executeRawUnsafe(
        `DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`
      );

      // Clear cache
      this.tenantCache.delete(tenantId);

      return true;
    } catch (error) {
      console.error(`Error dropping schema for tenant ${tenantId}:`, error);
      return false;
    }
  }

  /**
   * Disconnect all tenant clients
   */
  public async disconnectAll(): Promise<void> {
    const disconnectPromises = Array.from(this.prismaClients.values()).map(
      client => client.$disconnect()
    );
    
    await Promise.all(disconnectPromises);
    this.prismaClients.clear();
    
    await this.masterClient.$disconnect();
  }

  /**
   * Clear tenant cache
   */
  public clearCache(tenantId?: string): void {
    if (tenantId) {
      this.tenantCache.delete(tenantId);
    } else {
      this.tenantCache.clear();
    }
  }
}
