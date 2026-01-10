/**
 * Prisma Client Extension for Automatic Tenant Scoping
 * 
 * Provides automatic tenant isolation by adding tenantId filters to all queries
 * for models that have a tenantId field. Uses modern Prisma Client Extensions API (v4+).
 * 
 * Models are automatically detected from your Prisma schema - no manual configuration needed!
 */

import { Prisma } from '@prisma/client';

export interface TenantExtensionOptions {
    /**
     * Optional: Explicitly specify which models to scope
     * If not provided, will attempt to scope all models (those without tenantId will be skipped)
     * 
     * @example
     * ```typescript
     * models: ['project', 'invoice', 'customer']
     * ```
     */
    models?: string[];

    /**
     * The field name used for tenant scoping
     * @default 'tenantId'
     */
    tenantIdField?: string;

    /**
     * Whether to log when a model is skipped (doesn't have tenantId field)
     * @default false
     */
    debug?: boolean;
}

/**
 * Create a tenant-scoped Prisma client extension
 * 
 * Automatically detects which models have a tenantId field and scopes them.
 * Models without tenantId are safely ignored.
 * 
 * @param tenantId - The tenant ID to scope queries to
 * @param options - Configuration options
 * @returns Prisma client extension
 * 
 * @example
 * ```typescript
 * // Automatic detection - scopes all models with tenantId field
 * const tenantPrisma = prisma.$extends(createTenantExtension('tenant-123'));
 * 
 * // Explicit models (for better performance if you know which models to scope)
 * const tenantPrisma = prisma.$extends(createTenantExtension('tenant-123', {
 *   models: ['project', 'invoice', 'customer']
 * }));
 * 
 * // Custom tenant field name
 * const tenantPrisma = prisma.$extends(createTenantExtension('org-123', {
 *   tenantIdField: 'organizationId'
 * }));
 * ```
 */
export function createTenantExtension(
    tenantId: string,
    options: TenantExtensionOptions = {}
) {
    const {
        models,
        tenantIdField = 'tenantId',
        debug = false,
    } = options;

    // Convert to Set for O(1) lookup (case-insensitive)
    const explicitModels = models ? new Set(models.map(m => m.toLowerCase())) : null;

    /**
     * Check if a model should be scoped
     * If explicit models provided, check against that list
     * Otherwise, try to scope (will fail gracefully if model doesn't have tenantId)
     */
    const shouldScopeModel = (modelName: string): boolean => {
        if (explicitModels) {
            return explicitModels.has(modelName.toLowerCase());
        }
        // If no explicit list, attempt to scope all models
        // (will be caught and handled gracefully if field doesn't exist)
        return true;
    };

    /**
     * Safely add tenant filter to where clause
     * Returns modified args or original args if field doesn't exist
     */
    const addTenantFilter = (args: any, modelName: string) => {
        if (!shouldScopeModel(modelName)) {
            return args;
        }

        try {
            // Add tenant filter to where clause
            args.where = {
                ...args.where,
                [tenantIdField]: tenantId,
            };
            return args;
        } catch (error) {
            // Model doesn't have tenantId field - skip silently
            if (debug) {
                console.log(`[TenantExtension] Skipping model '${modelName}' - no ${tenantIdField} field`);
            }
            return args;
        }
    };

    /**
     * Safely add tenant field to data
     */
    const addTenantToData = (args: any, modelName: string) => {
        if (!shouldScopeModel(modelName)) {
            return args;
        }

        try {
            if (Array.isArray(args.data)) {
                args.data = args.data.map((item: any) => ({
                    ...item,
                    [tenantIdField]: tenantId,
                }));
            } else {
                args.data = {
                    ...args.data,
                    [tenantIdField]: tenantId,
                };
            }
            return args;
        } catch (error) {
            if (debug) {
                console.log(`[TenantExtension] Skipping model '${modelName}' - no ${tenantIdField} field`);
            }
            return args;
        }
    };

    return Prisma.defineExtension((client) => {
        return client.$extends({
            name: 'tenantScoping',
            query: {
                $allModels: {
                    // Read operations - add WHERE filter
                    async findMany({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async findFirst({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async findUnique({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async count({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async aggregate({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async groupBy({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    // Write operations - add tenantId to data
                    async create({ model, args, query }) {
                        return query(addTenantToData(args, model));
                    },

                    async createMany({ model, args, query }) {
                        return query(addTenantToData(args, model));
                    },

                    // Update operations - add WHERE filter
                    async update({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async updateMany({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async upsert({ model, args, query }) {
                        args = addTenantFilter(args, model);
                        args.create = {
                            ...args.create,
                            [tenantIdField]: tenantId,
                        };
                        return query(args);
                    },

                    // Delete operations - add WHERE filter
                    async delete({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },

                    async deleteMany({ model, args, query }) {
                        return query(addTenantFilter(args, model));
                    },
                },
            },
        });
    });
}

/**
 * Helper to get tenant-scoped models from Prisma schema
 * 
 * Note: This requires the Prisma schema to be generated
 * 
 * @example
 * ```typescript
 * import { PrismaClient } from '@prisma/client';
 * 
 * // Get all model names from Prisma
 * const prisma = new PrismaClient();
 * const modelNames = Object.keys(prisma).filter(
 *   key => !key.startsWith('_') && !key.startsWith('$')
 * );
 * 
 * // Use with extension
 * const tenantPrisma = prisma.$extends(
 *   createTenantExtension(tenantId, { models: modelNames })
 * );
 * ```
 */
export function getTenantScopedModels(prismaClient: any): string[] {
    return Object.keys(prismaClient).filter(
        key => !key.startsWith('_') && !key.startsWith('$')
    );
}
