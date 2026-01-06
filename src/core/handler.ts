/**
 * Core API Handler Framework
 *
 * High-level abstraction for creating consistent, secure API routes with
 * authentication, validation, ownership checks, sanitization, encryption,
 * rate limiting, caching, and observability.
 */

import { z } from 'zod';
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

import {
  HandlerConfig,
  HandlerContext,
  User,
  TenantContext,
} from './types';
import {
  successResponse,
  errorResponse,
  validationErrorResponse,
  unauthorizedResponse,
  forbiddenResponse,
  rateLimitResponse,
  internalErrorResponse,
} from './response';

// Import services
import { AuthManager } from '../auth/manager';
import { SanitizationService } from '../security/sanitization';
import { EncryptionService } from '../security/encryption';
import { RedisRateLimiter } from '../security/rate-limiting';
import { CacheManager } from '../caching/manager';
import { AuditEventType, AuditCategory, AuditStatus, AuditSeverity } from '../audit/audit-types';
import { ServiceInitializer } from './service-initializer';
// ============================================
// Main Handler Factory
// ============================================

/**
 * Internal handler factory - DO NOT USE DIRECTLY
 * 
 * @internal
 * This is the base handler implementation. Use the public API instead:
 * - createPublicHandler() for public endpoints
 * - createAuthenticatedHandler() for authenticated endpoints
 * - createAdminHandler() for admin-only endpoints
 * - createTenantHandler() for tenant-scoped endpoints
 *
 * Automatically handles:
 * - Authentication & Authorization
 * - Input validation & sanitization
 * - Resource ownership verification
 * - Rate limiting
 * - Caching
 * - Error handling & monitoring
 * - Multi-tenancy
 * - API versioning
 */
function _createHandler<TInput = unknown, TOutput = unknown>(
  config: HandlerConfig<TInput, TOutput>
) {
  return async (req: Request, res: Response): Promise<any> => {
    const traceId = generateTraceId();
    const startTime = Date.now();

    // Get initialized services from ServiceInitializer
    const services = ServiceInitializer.getServices();
    const monitoring = services.monitoring!;
    const configManager = services.configManager!;
    const tenantManager = services.tenantManager!;
    const versionManager = services.versionManager!;
    const auditService = services.auditService!;

    let span: string | null = null;
    let auditEnabled = config.auditConfig?.enabled !== false;
    let user: User | null = null;
    let tenant: TenantContext | undefined;

    try {
      // Start monitoring span
      if (config.monitoring?.enableTracing) {
        span = monitoring.startSpan('handler', { traceId });
      }

      const params = req.params || {};
      const query = req.query || {};

      // ============================================
      // 1. Configuration & Feature Flags
      // ============================================

      if (config.featureFlags) {
        const featureFlags = configManager.getFeatureFlags();
        const disabledFeatures = config.featureFlags.filter(
          (flag: string) => !featureFlags[flag]
        );

        if (disabledFeatures.length > 0) {
          return errorResponse(
            res,
            'SERVICE_UNAVAILABLE',
            `Feature ${disabledFeatures[0]} is disabled`,
            503
          );
        }
      }

      // ============================================
      // 2. API Versioning
      // ============================================

      if (config.apiVersion) {
        const clientVersion = versionManager.getClientVersion(req);
        if (!versionManager.isVersionSupported(clientVersion, config.apiVersion)) {
          return errorResponse(
            res,
            'BAD_REQUEST',
            `API version ${clientVersion} is not supported. Required: ${config.apiVersion}`,
            400
          );
        }
      }

      // ============================================
      // 3. Multi-Tenant Context
      // ============================================

      if (tenantManager.isEnabled()) {
        const tenantId = await tenantManager.resolveTenantId(req);
        if (tenantId) {
          tenant = await tenantManager.getTenantContext(tenantId) || undefined;
        }

        // Only fail if tenant is required
        if (!tenant && configManager.getConfig().multitenancy.enabled) {
          return errorResponse(res, 'BAD_REQUEST', 'Invalid tenant', 400);
        }
      }

      // ============================================
      // 4. Authentication
      // ============================================

      if (config.requireAuth) {
        const authManager = AuthManager.getInstance();
        const strategies = config.authStrategies || ['jwt'];

        user = await authManager.authenticate(req, strategies);

        if (!user) {
          monitoring.recordMetric('auth.failure', 1, {
            method: req.method,
            path: req.path,
          });

          // Audit: Log authentication failure
          if (auditEnabled) {
            await auditService.logAuthEvent('login_failed', undefined, false, 'Authentication required', {
              request: req,
            });
          }

          return unauthorizedResponse(res, 'Authentication required');
        }

        monitoring.recordMetric('auth.success', 1, {
          method: req.method,
          user_role: user?.role || 'user',
        });

        // Audit: Log successful authentication
        if (auditEnabled && config.auditConfig?.trackDataChanges !== false) {
          await auditService.logAuthEvent('login', user.id, true, undefined, {
            user,
            request: req,
          });
        }

        // Role-based access control
        if (config.allowedRoles && config.allowedRoles.length > 0) {
          const userRole = user?.role || 'user';
          if (!config.allowedRoles.includes(userRole)) {
            monitoring.recordMetric('auth.forbidden', 1, {
              required_roles: config.allowedRoles.join(','),
              user_role: userRole,
            });
            return forbiddenResponse(res, 'Insufficient permissions for this operation');
          }
        }

        // Permission-based access control
        if (config.requiredPermissions && config.requiredPermissions.length > 0) {
          const hasPermissions = config.requiredPermissions.every(
            (permission: string) => user?.permissions?.includes(permission)
          );

          if (!hasPermissions) {
            monitoring.recordMetric('auth.forbidden', 1, {
              required_permissions: config.requiredPermissions.join(','),
            });
            return forbiddenResponse(res, 'Missing required permissions');
          }
        }
      }

      // ============================================
      // 5. Rate Limiting
      // ============================================

      if (config.rateLimit) {
        const rateLimiter = RedisRateLimiter.getInstance();
        const key = config.rateLimit.keyGenerator
          ? config.rateLimit.keyGenerator(req, user || undefined)
          : `rate-limit:${user?.id || req.ip}:${req.path}`;

        const isAllowed = await rateLimiter.checkLimit(key, config.rateLimit);

        if (!isAllowed) {
          monitoring.recordMetric('rate_limit.exceeded', 1, {
            key,
            method: req.method,
            path: req.path,
          });
          return rateLimitResponse(res, 'Rate limit exceeded');
        }
      }

      // ============================================
      // 6. Input Validation & Sanitization
      // ============================================

      let input: TInput;

      if (config.schema) {
        try {
          // Get request body from Express (already parsed by express.json())
          const body = req.method !== 'GET' ? req.body : {};

          // Combine body and query params for validation
          const rawInput = {
            ...body,
            ...query,
          };

          // Sanitize input
          const sanitizationService = SanitizationService.getInstance();
          const sanitizedInput = await sanitizationService.sanitize(rawInput);

          // Validate with Zod
          const parseResult = config.schema.safeParse(sanitizedInput);

          if (!parseResult.success) {
            const details = parseResult.error.flatten().fieldErrors;
            monitoring.recordMetric('validation.error', 1, {
              field_count: Object.keys(details).length.toString(),
            });
            return validationErrorResponse(res, 'Invalid input data', details);
          }

          input = parseResult.data;
        } catch (error) {
          if (error instanceof SyntaxError) {
            return validationErrorResponse(res, 'Invalid JSON in request body');
          }
          throw error;
        }
      } else {
        input = {} as TInput;
      }

      // ============================================
      // 7. Cache Check
      // ============================================

      if (config.cache && req.method === 'GET') {
        const cacheManager = CacheManager.getInstance();
        const cacheKey = config.cache.keyGenerator
          ? config.cache.keyGenerator(req, user || undefined)
          : `cache:${req.path}:${JSON.stringify(input)}`;

        const cached = await cacheManager.get(cacheKey);
        if (cached) {
          monitoring.recordMetric('cache.hit', 1, {
            key: cacheKey,
          });

          const executionTime = Date.now() - startTime;
          return successResponse(res, cached, undefined, 200, {
            executionTime,
            cached: true,
          });
        }

        monitoring.recordMetric('cache.miss', 1, {
          key: cacheKey,
        });
      }

      // ============================================
      // 8. Database Connection
      // ============================================

      let prisma: PrismaClient;

      if (tenant) {
        // Get tenant-specific connection
        prisma = await tenantManager.getPrismaClient(tenant.id);
      } else {
        // Use global Prisma instance (should be injected)
        // For now, create a new instance (in production, use dependency injection)
        prisma = (global as any).prisma || new PrismaClient();
      }

      // ============================================
      // 9. Resource Ownership Verification
      // ============================================

      let resource: any = undefined;

      if (config.requireOwnership && user) {
        const { model, resourceIdParam, resourceIdField, ownerIdField, tenantIdField, selectFields } = config.requireOwnership;
        const resourceId = params[resourceIdParam];

        if (!resourceId) {
          return validationErrorResponse(res, `Missing required parameter: ${resourceIdParam}`);
        }

        try {
          // Build Prisma query with ownership filters
          const where: any = {
            [resourceIdField || 'id']: resourceId,
          };

          // Add owner/tenant filter
          if (ownerIdField && user.tenant_id) {
            where[ownerIdField] = user.tenant_id;
          }

          // Add tenant filter
          if (tenantIdField && tenant?.id) {
            where[tenantIdField] = tenant.id;
          }

          // Query using Prisma
          const modelName = model.toLowerCase();
          resource = await (prisma as any)[modelName].findFirst({
            where,
            select: selectFields ? Object.fromEntries(selectFields.map((f: string) => [f, true])) : undefined,
          });

          if (!resource) {
            monitoring.recordMetric('ownership.verification_failed', 1, {
              model,
              resource_id: resourceId,
            });

            // Audit: Log authorization failure
            if (auditEnabled) {
              await auditService.logSecurityEvent(
                'authorization.failed',
                AuditSeverity.WARNING,
                `Access denied to ${model} ${resourceId}`,
                { model, resourceId },
                { user, tenant, request: req }
              );
            }

            return forbiddenResponse(res, 'Resource not found or access denied');
          }
        } catch (error) {
          console.error('Ownership verification error:', error);
          return forbiddenResponse(res, 'Resource verification failed');
        }
      }

      // ============================================
      // 10. Execute Handler
      // ============================================

      const handlerContext: HandlerContext<TInput> = {
        input,
        user,
        prisma,
        params,
        query,
        request: req,
        ...(resource ? { resource } : {}),
        ...(tenant ? { tenant } : {}),
        trace: {
          traceId,
          spanId: generateSpanId(),
          startTime: new Date(startTime),
          tags: {
            method: req.method,
            path: req.path,
            user_id: user?.id || '',
            tenant_id: tenant?.id || '',
          },
        },
      };

      // Capture old data for UPDATE/DELETE operations (for audit trail)
      let oldData: any;
      if (auditEnabled && config.auditConfig?.trackDataChanges && resource) {
        oldData = { ...resource };
      }

      const result = await config.handler(handlerContext);

      // ============================================
      // 11. Auto-sanitize and encrypt response
      // ============================================

      let processedResult = result;

      // Sanitize response
      const shouldSanitize = config.sanitizeResponse !== false;
      if (shouldSanitize) {
        const sanitizationService = SanitizationService.getInstance();
        processedResult = await sanitizationService.sanitizeResponse(processedResult);
        monitoring.recordMetric('sanitization.applied', 1);
      }

      // Encrypt sensitive fields if configured (skip if no encryption key)
      try {
        const encryptionService = EncryptionService.getInstance({
          key: process.env.ENCRYPTION_KEY || 'dev-key-change-in-production-32chars!!!',
        });
        processedResult = await encryptionService.processResponse(processedResult);
      } catch (error) {
        // Skip encryption if service is not properly configured
        if (process.env.NODE_ENV === 'development') {
          console.warn('Encryption service not configured, skipping encryption');
        }
      }

      // ============================================
      // 12. Cache Result
      // ============================================

      if (config.cache && req.method === 'GET') {
        const cacheManager = CacheManager.getInstance();
        const cacheKey = config.cache.keyGenerator
          ? config.cache.keyGenerator(req, user || undefined)
          : `cache:${req.path}:${JSON.stringify(input)}`;

        await cacheManager.set(cacheKey, processedResult, config.cache.ttl);
      }

      // ============================================
      // 13. Success Response
      // ============================================

      const executionTime = Date.now() - startTime;
      monitoring.recordMetric('handler.success', 1, {
        method: req.method,
        path: req.path,
        execution_time: executionTime.toString(),
      });

      // Audit: Log successful operation
      if (auditEnabled) {
        const eventType = mapMethodToAuditEventType(req.method);
        const resourceType = config.auditConfig?.resourceType || config.requireOwnership?.model;
        const resourceId = config.requireOwnership?.resourceIdParam ? params[config.requireOwnership.resourceIdParam] : undefined;

        await auditService.logEvent(
          {
            eventType,
            category: config.auditConfig?.category as any || AuditCategory.DATA,
            action: config.auditConfig?.action || `${req.method.toLowerCase()}.${req.path}`,
            description: `${req.method} ${req.path}`,
            ...(resourceType ? { resourceType } : {}),
            ...(resourceId ? { resourceId } : {}),
            ...(config.auditConfig?.trackDataChanges ? { oldData } : {}),
            ...(config.auditConfig?.captureResponseBody ? { newData: processedResult } : {}),
            status: AuditStatus.SUCCESS,
            statusCode: config.successStatus || 200,
            severity: AuditSeverity.INFO,
            executionTimeMs: executionTime,
            ...(config.auditConfig?.metadata ? { metadata: config.auditConfig.metadata } : {}),
            ...(config.auditConfig?.tags ? { tags: config.auditConfig.tags } : {}),
            ...(config.auditConfig?.retentionCategory ? { retentionCategory: config.auditConfig.retentionCategory } : {}),
          },
          {
            user,
            ...(tenant ? { tenant } : {}),
            request: req,
            traceId,
          }
        );
      }

      return successResponse(res, processedResult, undefined, config.successStatus, {
        executionTime,
      });

    } catch (error: any) {
      const executionTime = Date.now() - startTime;

      // Record error metrics
      monitoring.recordMetric('handler.error', 1, {
        method: req.method,
        path: req.path,
        error_type: error.constructor.name,
        execution_time: executionTime.toString(),
      });

      console.error('[API Handler Error]', {
        method: req.method,
        url: req.url,
        error: error.message,
        traceId,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      });

      // Audit: Log error
      if (auditEnabled) {
        const eventType = mapMethodToAuditEventType(req.method);
        await auditService.logEvent(
          {
            eventType,
            category: AuditCategory.SYSTEM,
            action: `${req.method.toLowerCase()}.error`,
            description: `Error in ${req.method} ${req.path}`,
            status: AuditStatus.FAILURE,
            errorMessage: error.message,
            severity: AuditSeverity.ERROR,
            executionTimeMs: executionTime,
            metadata: {
              errorType: error.constructor.name,
              stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
            },
          },
          {
            user,
            tenant,
            request: req,
            traceId,
          }
        );
      }

      // Close monitoring span
      if (span) {
        monitoring.endSpan(span, 'error', error.message);
      }

      // Zod validation errors
      if (error instanceof z.ZodError) {
        return validationErrorResponse(
          res,
          'Validation failed',
          error.flatten().fieldErrors
        );
      }

      // Return generic error (don't expose internal details)
      return internalErrorResponse(
        res,
        process.env.NODE_ENV === 'development'
          ? `Internal error: ${error.message}`
          : 'An unexpected error occurred'
      );
    } finally {
      // End monitoring span
      if (span) {
        monitoring.endSpan(span);
      }
    }
  };
}

// ============================================
// Convenience Wrappers
// ============================================

/**
 * Create an authenticated handler (requires login)
 * 
 * Use when:
 * - The endpoint requires a logged-in user
 * - You need to access user information (user.id, user.email, etc.)
 * - The resource should only be accessible to authenticated users
 * - No specific role restrictions are needed (any authenticated user can access)
 * 
 * Example: User profile endpoints, user settings, personal dashboards
 */
export const createAuthenticatedHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth'>
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({ ...config, requireAuth: true });
};

/**
 * Create a public handler (no authentication required)
 * 
 * Use when:
 * - The endpoint should be accessible without login
 * - Public data or resources are being served
 * - Authentication is optional or not needed
 * - The endpoint is part of a public API
 * 
 * Example: Public content, health checks, documentation endpoints, login/signup
 */
export const createPublicHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth'>
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({ ...config, requireAuth: false });
};

/**
 * Create a super admin-only handler
 * 
 * Use when:
 * - The endpoint performs critical system operations
 * - Only the highest privilege level should have access
 * - Managing system-wide settings or configurations
 * - Performing operations that affect all tenants
 * 
 * Example: System configuration, user management, tenant provisioning, audit log access
 */
export const createSuperAdminHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth' | 'allowedRoles'>
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({
    ...config,
    requireAuth: true,
    allowedRoles: ['superadmin'],
  });
};

/**
 * Create a tenant-scoped handler
 * 
 * Use when:
 * - The endpoint operates within a multi-tenant context
 * - Data should be automatically scoped to the user's tenant
 * - Tenant isolation is required
 * - The resource belongs to a specific tenant
 * 
 * Example: Tenant-specific resources, organization settings, team management
 */
export const createTenantHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth'>
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({
    ...config,
    requireAuth: true,
    featureFlags: ['multitenancy'],
  });
};

// ============================================
// Utility Functions
// ============================================

function generateTraceId(): string {
  return `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateSpanId(): string {
  return `span_${Math.random().toString(36).substr(2, 9)}`;
}

function mapMethodToAuditEventType(method: string): AuditEventType {
  switch (method.toUpperCase()) {
    case 'POST':
      return AuditEventType.CREATE;
    case 'GET':
      return AuditEventType.READ;
    case 'PUT':
    case 'PATCH':
      return AuditEventType.UPDATE;
    case 'DELETE':
      return AuditEventType.DELETE;
    default:
      return AuditEventType.CUSTOM;
  }
}
