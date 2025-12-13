/**
 * Shared Schema Tenant Strategy
 * 
 * All tenants share the same database schema with tenant_id filtering.
 * This is the simplest and most cost-effective approach but provides the least isolation.
 * 
 * Pros:
 * - Simple to implement and maintain
 * - Cost-effective (single database)
 * - Easy schema updates
 * 
 * Cons:
 * - Least data isolation
 * - Risk of data leakage if queries aren't properly filtered
 * - All tenants affected by database issues
 */

import { Request } from 'express';
import { PrismaClient } from '@prisma/client';
import { TenantContext } from '../../core/types';
import { TenantStrategy } from '../manager';

export interface SharedSchemaConfig {
  prismaClient: PrismaClient;
  tenantIdField?: string;
  cacheTtl?: number;
}

export class SharedSchemaStrategy implements TenantStrategy {
  public readonly name = 'shared_schema';
  private prismaClient: PrismaClient;
  private tenantIdField: string;
  private tenantCache: Map<string, TenantContext> = new Map();
  private cacheTtl: number;

  constructor(config: SharedSchemaConfig) {
    this.prismaClient = config.prismaClient;
    this.tenantIdField = config.tenantIdField || 'tenantId';
    this.cacheTtl = config.cacheTtl || 5 * 60 * 1000; // 5 minutes default
  }

  /**
   * Get Prisma client for tenant
   * In shared schema, all tenants use the same Prisma client
   */
  public async getPrismaClient(tenantId: string): Promise<PrismaClient> {
    // Validate tenant exists
    await this.validateTenant(tenantId);
    
    // Return the shared Prisma client
    // Note: Queries must be manually filtered by tenant_id
    return this.prismaClient;
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
      // Check if tenant exists in the database
      const tenant = await (this.prismaClient as any).tenant.findUnique({
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
      // Fetch tenant from database
      const tenant = await (this.prismaClient as any).tenant.findUnique({
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

      const context: TenantContext = {
        id: tenant.id,
        name: tenant.name,
        config: tenant.config || {},
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
   * Create Prisma middleware for automatic tenant filtering
   * This ensures all queries are automatically filtered by tenant_id
   */
  public createTenantMiddleware(tenantId: string) {
    return async (params: any, next: any) => {
      // Skip for tenant-related queries to avoid infinite loops
      if (params.model === 'Tenant') {
        return next(params);
      }

      // Add tenant_id filter to all queries
      if (params.action === 'findUnique' || params.action === 'findFirst') {
        params.args.where = params.args.where || {};
        params.args.where[this.tenantIdField] = tenantId;
      }

      if (params.action === 'findMany') {
        params.args.where = params.args.where || {};
        params.args.where[this.tenantIdField] = tenantId;
      }

      if (params.action === 'create') {
        params.args.data = params.args.data || {};
        params.args.data[this.tenantIdField] = tenantId;
      }

      if (params.action === 'createMany') {
        if (Array.isArray(params.args.data)) {
          params.args.data = params.args.data.map((item: any) => ({
            ...item,
            [this.tenantIdField]: tenantId,
          }));
        }
      }

      if (params.action === 'update' || params.action === 'updateMany') {
        params.args.where = params.args.where || {};
        params.args.where[this.tenantIdField] = tenantId;
      }

      if (params.action === 'delete' || params.action === 'deleteMany') {
        params.args.where = params.args.where || {};
        params.args.where[this.tenantIdField] = tenantId;
      }

      if (params.action === 'upsert') {
        params.args.where = params.args.where || {};
        params.args.where[this.tenantIdField] = tenantId;
        params.args.create = params.args.create || {};
        params.args.create[this.tenantIdField] = tenantId;
      }

      return next(params);
    };
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

  /**
   * Get tenant ID field name
   */
  public getTenantIdField(): string {
    return this.tenantIdField;
  }
}
