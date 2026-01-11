/**
 * Enhanced Core API Handler Framework
 *
 * High-level abstraction for creating consistent, secure API routes with
 * authentication, validation, ownership checks, sanitization, encryption,
 * rate limiting, caching, and observability.
 *
 * SECURITY ENHANCEMENTS:
 * - Fixed hardcoded encryption key vulnerability
 * - Fixed Prisma middleware race condition
 * - Fixed cache poisoning with tenant isolation
 * - Added SQL injection protection
 * - Added transaction support
 * - Added CSRF protection
 * - Fixed monitoring span leaks
 * - Added request timeouts
 * - Added idempotency support
 * - Deep cloning for audit trail
 * - Improved error sanitization
 */

import { z } from 'zod';
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

import crypto from 'crypto';

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
import { CSRFProtection } from '../security/csrf';
import { IdempotencyService } from '../security/idempotency';
import { createTenantExtension } from '../database/prisma-tenant-extension';

// ============================================
// Constants & Configuration
// ============================================

const ALLOWED_PRISMA_MODELS = [
  'user',
  'project',
  'task',
  'auditLog',
  'tenant',
  'tenantMember',
  'organization',
  'document',
  'comment',
] as const;

type AllowedModel = typeof ALLOWED_PRISMA_MODELS[number];

const TENANT_SCOPED_MODELS = new Set([
  'project',
  'task',
  'auditLog',
  'document',
  'comment',
]);

const DEFAULT_REQUEST_TIMEOUT = 30000; // 30 seconds
const MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024; // 10MB

// State-changing HTTP methods that require CSRF protection
const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// ============================================
// Enhanced Types
// ============================================

interface EnhancedHandlerContext<TInput> extends HandlerContext<TInput> {
  transaction: <T>(fn: (tx: PrismaClient) => Promise<T>) => Promise<T>;
  idempotencyKey?: string;
}

interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number;
}

// ============================================
// Utility Functions
// ============================================

function generateSecureTraceId(): string {
  return `trace_${Date.now()}_${crypto.randomUUID()}`;
}

function generateSpanId(): string {
  return `span_${crypto.randomUUID()}`;
}

/**
 * Stable JSON stringify that sorts keys for deterministic output
 */
function stableStringify(obj: any): string {
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return String(obj);

  if (Array.isArray(obj)) {
    return `[${obj.map(stableStringify).join(',')}]`;
  }

  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => `"${k}":${stableStringify(obj[k])}`);
  return `{${pairs.join(',')}}`;
}

/**
 * Deep clone an object for audit trail
 */
function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') return obj;

  if (obj instanceof Date) return new Date(obj.getTime()) as any;
  if (obj instanceof Array) return obj.map(item => deepClone(item)) as any;
  if (obj instanceof Set) return new Set(Array.from(obj).map(deepClone)) as any;
  if (obj instanceof Map) {
    return new Map(Array.from(obj.entries()).map(([k, v]) => [k, deepClone(v)])) as any;
  }

  const cloned = {} as T;
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      cloned[key] = deepClone(obj[key]);
    }
  }
  return cloned;
}

/**
 * Sanitize error message for safe logging
 */
function sanitizeErrorMessage(message: string): string {
  // Remove potential SQL fragments
  let sanitized = message.replace(/SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER/gi, '[SQL]');

  // Remove potential file paths
  sanitized = sanitized.replace(/[A-Za-z]:\\[\w\\.-]+|\/[\w\/.-]+/g, '[PATH]');

  // Remove email addresses
  sanitized = sanitized.replace(/[\w.-]+@[\w.-]+\.\w+/g, '[EMAIL]');

  // Remove potential API keys/tokens (common patterns)
  sanitized = sanitized.replace(/[a-zA-Z0-9_-]{32,}/g, '[TOKEN]');

  return sanitized;
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

/**
 * Validate that a model name is in the allowed list
 */
function validateModelName(model: string): model is AllowedModel {
  return ALLOWED_PRISMA_MODELS.includes(model as AllowedModel);
}

/**
 * Generate a secure cache key with proper isolation and hashing
 * Uses SHA-256 to hash input data to prevent cache key length issues
 */
function generateCacheKey(
  path: string,
  input: any,
  userId?: string,
  tenantId?: string
): string {
  // Hash the input to prevent cache key length issues and improve security
  const inputHash = crypto
    .createHash('sha256')
    .update(stableStringify(input))
    .digest('hex')
    .substring(0, 16); // First 16 chars for brevity

  const parts = [
    'cache',
    path,
    tenantId || 'global',
    userId || 'anon',
    inputHash,
  ];

  return parts.join(':');
}

// ============================================
// Enhanced Service Initialization
// ============================================

interface RequiredServices {
  monitoring: any;
  configManager: any;
  tenantManager: any;
  versionManager: any;
  auditService: any;
  encryptionService?: EncryptionService;
  csrfProtection?: CSRFProtection;
  idempotencyService?: IdempotencyService;
}

/**
 * Validate and get required services with proper error handling
 */
function getRequiredServices(): RequiredServices {
  const services = ServiceInitializer.getServices();

  if (!services.monitoring) {
    throw new Error('Monitoring service not initialized');
  }
  if (!services.configManager) {
    throw new Error('ConfigManager service not initialized');
  }
  if (!services.tenantManager) {
    throw new Error('TenantManager service not initialized');
  }
  if (!services.versionManager) {
    throw new Error('VersionManager service not initialized');
  }
  if (!services.auditService) {
    throw new Error('AuditService not initialized');
  }

  return services as RequiredServices;
}

/**
 * Initialize encryption service with proper validation
 */
function initializeEncryptionService(): EncryptionService {
  const encryptionKey = process.env.ENCRYPTION_KEY;

  if (!encryptionKey) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('ENCRYPTION_KEY environment variable must be set in production');
    }
    console.warn('⚠️  ENCRYPTION_KEY not set - using development key (DO NOT USE IN PRODUCTION)');
  }

  const key = encryptionKey || 'dev-key-change-in-production-32chars!!!';

  if (key.length < 32) {
    throw new Error('ENCRYPTION_KEY must be at least 32 characters');
  }

  return EncryptionService.getInstance({ key });
}

/**
 * Get or create tenant-aware Prisma client with proper connection management
 */
async function getPrismaClient(
  tenantId: string | undefined,
  tenantManager: any,
  globalPrisma: PrismaClient
): Promise<PrismaClient> {
  if (tenantId) {
    return await tenantManager.getPrismaClient(tenantId);
  }

  if (!globalPrisma) {
    throw new Error('Global Prisma client not provided. Please inject via dependency injection.');
  }

  return globalPrisma;
}

// ============================================
// Prisma Middleware Factory
// ============================================

/**
 * Create tenant-scoping middleware (should be applied once during initialization)
 */
function createTenantScopingMiddleware(tenantId: string) {
  return async (params: any, next: any) => {
    const modelName = params.model?.toLowerCase();

    if (modelName && TENANT_SCOPED_MODELS.has(modelName)) {
      // Add tenant filter to WHERE clause
      if (['findMany', 'findFirst', 'findUnique', 'count', 'aggregate'].includes(params.action)) {
        params.args.where = {
          ...params.args.where,
          tenantId,
        };
      }

      // Add tenant to CREATE operations
      if (params.action === 'create') {
        params.args.data = {
          ...params.args.data,
          tenantId,
        };
      }

      // Add tenant to CREATE MANY operations
      if (params.action === 'createMany') {
        if (Array.isArray(params.args.data)) {
          params.args.data = params.args.data.map((item: any) => ({
            ...item,
            tenantId,
          }));
        } else {
          params.args.data = {
            ...params.args.data,
            tenantId,
          };
        }
      }

      // Add tenant to UPDATE operations
      if (['update', 'updateMany'].includes(params.action)) {
        params.args.where = {
          ...params.args.where,
          tenantId,
        };
      }

      // Add tenant to DELETE operations
      if (['delete', 'deleteMany'].includes(params.action)) {
        params.args.where = {
          ...params.args.where,
          tenantId,
        };
      }
    }

    return next(params);
  };
}

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
 * - createSuperAdminHandler() for admin-only endpoints
 * - createTenantHandler() for tenant-scoped endpoints
 *
 * SECURITY ENHANCEMENTS:
 * - Fixed encryption key validation
 * - Fixed Prisma middleware race conditions
 * - Fixed cache poisoning
 * - Added SQL injection protection
 * - Added CSRF protection
 * - Added request timeouts
 * - Added idempotency support
 * - Improved error sanitization
 * - Fixed monitoring span leaks
 * - Deep cloning for audit trail
 */
function _createHandler<TInput = unknown, TOutput = unknown>(
  config: HandlerConfig<TInput, TOutput>,
  injectedPrisma?: PrismaClient
) {
  // Apply security preset if specified
  let effectiveConfig = config;

  if (config.preset) {
    const { mergePresetConfig } = require('./security-presets');
    effectiveConfig = mergePresetConfig(config.preset, config);
  }

  return async (req: Request, res: Response): Promise<any> => {
    const traceId = generateSecureTraceId();
    const startTime = Date.now();

    let span: string | null = null;
    let auditEnabled = effectiveConfig.auditConfig?.enabled !== false;
    let user: User | null = null;
    let tenant: TenantContext | undefined;
    let prisma: any = null;
    let monitoring: any;
    let auditService: any;

    // Wrap everything in try-finally to ensure cleanup
    try {
      // ============================================
      // 0. Service Initialization & Validation
      // ============================================

      const services = getRequiredServices();
      monitoring = services.monitoring;
      auditService = services.auditService;
      const { configManager, tenantManager, versionManager } = services;

      // Initialize optional services
      const encryptionService = initializeEncryptionService();
      const csrfProtection = services.csrfProtection || CSRFProtection.getInstance();
      const idempotencyService = services.idempotencyService || IdempotencyService.getInstance();

      // Start monitoring span
      if (effectiveConfig.monitoring?.enableTracing) {
        span = monitoring.startSpan('handler', { traceId });
      }

      const params = req.params || {};
      const query = req.query || {};

      // ============================================
      // 0a. Request Size Validation
      // ============================================

      const contentLength = parseInt(req.get('content-length') || '0', 10);
      if (contentLength > MAX_REQUEST_BODY_SIZE) {
        monitoring.recordMetric('request.too_large', 1, {
          size: contentLength.toString(),
        });
        return errorResponse(res, 'PAYLOAD_TOO_LARGE', 'Request body too large', 413);
      }

      // ============================================
      // 0b. Content-Type Validation
      // ============================================

      if (STATE_CHANGING_METHODS.has(req.method)) {
        const contentType = req.get('content-type');
        if (contentType && !contentType.includes('application/json') && !contentType.includes('multipart/form-data')) {
          return errorResponse(res, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json', 415);
        }
      }

      // ============================================
      // 1. Configuration & Feature Flags
      // ============================================

      if (effectiveConfig.featureFlags) {
        const featureFlags = configManager.getFeatureFlags();
        const disabledFeatures = effectiveConfig.featureFlags.filter(
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

      if (effectiveConfig.apiVersion) {
        const clientVersion = versionManager.getClientVersion(req);
        if (!versionManager.isVersionSupported(clientVersion, effectiveConfig.apiVersion)) {
          return errorResponse(
            res,
            'BAD_REQUEST',
            `API version ${clientVersion} is not supported. Required: ${effectiveConfig.apiVersion}`,
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

      if (effectiveConfig.requireAuth) {
        const authManager = AuthManager.getInstance();
        const strategies = effectiveConfig.authStrategies || ['jwt'];

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
        if (auditEnabled && effectiveConfig.auditConfig?.trackDataChanges !== false) {
          await auditService.logAuthEvent('login', user.id, true, undefined, {
            user,
            request: req,
          });
        }

        // Role-based access control (global check)
        if (effectiveConfig.allowedRoles && effectiveConfig.allowedRoles.length > 0) {
          const userRole = user?.role || 'user';

          // Note: Tenant-scoped role validation happens after Prisma initialization
          if (!tenant && !effectiveConfig.allowedRoles.includes(userRole)) {
            monitoring.recordMetric('auth.forbidden', 1, {
              required_roles: effectiveConfig.allowedRoles.join(','),
              user_role: userRole,
            });
            return forbiddenResponse(res, 'Insufficient permissions for this operation');
          }
        }

        // Permission-based access control
        if (effectiveConfig.requiredPermissions && effectiveConfig.requiredPermissions.length > 0) {
          const userPermissions = user?.permissions || [];
          const hasPermissions = effectiveConfig.requiredPermissions.every(
            (permission: string) => userPermissions.includes(permission)
          );

          if (!hasPermissions) {
            monitoring.recordMetric('auth.forbidden', 1, {
              required_permissions: effectiveConfig.requiredPermissions.join(','),
            });
            return forbiddenResponse(res, 'Missing required permissions');
          }
        }
      }

      // ============================================
      // 5. CSRF Protection
      // ============================================

      if (STATE_CHANGING_METHODS.has(req.method) && effectiveConfig.requireAuth && effectiveConfig.csrfProtection !== false) {
        const csrfToken = req.get('X-CSRF-Token') || req.body?._csrf;

        if (!csrfToken) {
          monitoring.recordMetric('csrf.missing_token', 1);
          return forbiddenResponse(res, 'CSRF token required');
        }

        const isValidCsrf = await csrfProtection.validateToken(csrfToken, user?.id);

        if (!isValidCsrf) {
          monitoring.recordMetric('csrf.invalid_token', 1);

          if (auditEnabled) {
            await auditService.logSecurityEvent(
              'csrf.validation.failed',
              AuditSeverity.WARNING,
              'Invalid CSRF token',
              { userId: user?.id },
              { user, request: req }
            );
          }

          return forbiddenResponse(res, 'Invalid CSRF token');
        }

        monitoring.recordMetric('csrf.valid', 1);
      }

      // ============================================
      // 6. Rate Limiting
      // ============================================

      let rateLimitInfo: RateLimitInfo | undefined;

      if (effectiveConfig.rateLimit) {
        const rateLimiter = RedisRateLimiter.getInstance();
        const key = effectiveConfig.rateLimit.keyGenerator
          ? effectiveConfig.rateLimit.keyGenerator(req, user || undefined)
          : `rate-limit:${user?.id || req.ip}:${req.path}`;

        const result = await rateLimiter.getLimitInfo(key, effectiveConfig.rateLimit);

        if (!result.allowed) {
          monitoring.recordMetric('rate_limit.exceeded', 1, {
            key,
            method: req.method,
            path: req.path,
          });

          const resetAt = result.resetTime.getTime();

          // Add rate limit headers
          res.set({
            'X-RateLimit-Limit': effectiveConfig.rateLimit.maxRequests.toString(),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': resetAt.toString(),
            'Retry-After': Math.ceil((resetAt - Date.now()) / 1000).toString(),
          });

          return rateLimitResponse(res, 'Rate limit exceeded');
        }

        const resetAt = result.resetTime.getTime();

        rateLimitInfo = {
          limit: effectiveConfig.rateLimit.maxRequests,
          remaining: result.remaining,
          reset: resetAt,
        };

        // Add rate limit headers to successful responses
        res.set({
          'X-RateLimit-Limit': effectiveConfig.rateLimit.maxRequests.toString(),
          'X-RateLimit-Remaining': result.remaining.toString(),
          'X-RateLimit-Reset': resetAt.toString(),
        });
      }

      // ============================================
      // 7. Input Validation & Sanitization
      // ============================================

      let input: TInput;

      if (effectiveConfig.schema) {
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
          const parseResult = effectiveConfig.schema.safeParse(sanitizedInput);

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
      // 8. Idempotency Check
      // ============================================

      let idempotencyKey: string | undefined;

      if (STATE_CHANGING_METHODS.has(req.method) && effectiveConfig.idempotency !== false) {
        idempotencyKey = req.get('Idempotency-Key');

        if (idempotencyKey) {
          // Validate idempotency key format (prevent injection attacks)
          if (!/^[a-zA-Z0-9_-]{1,255}$/.test(idempotencyKey)) {
            monitoring.recordMetric('idempotency.invalid_key', 1);
            return errorResponse(res, 'BAD_REQUEST', 'Invalid Idempotency-Key format. Must be alphanumeric, dash, or underscore (1-255 chars)', 400);
          }

          const cachedResponse = await idempotencyService.get(idempotencyKey);

          if (cachedResponse) {
            monitoring.recordMetric('idempotency.hit', 1);

            // Return cached response
            return successResponse(
              res,
              cachedResponse.data,
              undefined,
              cachedResponse.statusCode,
              {
                executionTime: 0,
                cached: true,
                idempotent: true,
              }
            );
          }

          monitoring.recordMetric('idempotency.miss', 1);
        }
      }

      // ============================================
      // 9. Cache Check
      // ============================================

      if (effectiveConfig.cache && req.method === 'GET') {
        const cacheManager = CacheManager.getInstance();
        const cacheKey = effectiveConfig.cache.keyGenerator
          ? effectiveConfig.cache.keyGenerator(req, user || undefined)
          : generateCacheKey(req.path, input, user?.id, tenant?.id);

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
      // 10. Database Connection
      // ============================================

      prisma = await getPrismaClient(tenant?.id, tenantManager, injectedPrisma!);

      // ============================================
      // 10a. Tenant-Scoped Role Validation
      // ============================================

      if (tenant && effectiveConfig.allowedRoles && effectiveConfig.allowedRoles.length > 0 && effectiveConfig.tenantRoleValidation !== false) {
        try {
          // Check if user has required role in THIS tenant
          const tenantMembership = await prisma.tenantMember.findFirst({
            where: {
              userId: user!.id,
              tenantId: tenant!.id,
              role: { in: effectiveConfig.allowedRoles as any[] },
              isActive: true,
            },
          });

          if (!tenantMembership) {
            monitoring.recordMetric('auth.tenant_role_forbidden', 1, {
              required_roles: effectiveConfig.allowedRoles.join(','),
              user_role: user?.role || 'unknown',
              tenant_id: tenant.id,
            });

            // Audit: Log tenant authorization failure
            if (auditEnabled) {
              await auditService.logSecurityEvent(
                'tenant.authorization.failed',
                AuditSeverity.WARNING,
                `User ${user!.id} attempted to access tenant ${tenant.id} with insufficient role`,
                { required_roles: effectiveConfig.allowedRoles, user_role: user?.role },
                { user, tenant, request: req }
              );
            }

            return forbiddenResponse(
              res,
              `Insufficient permissions in this tenant. Required: ${effectiveConfig.allowedRoles.join(' or ')}`
            );
          }

          // Success - user has required role in this tenant
          monitoring.recordMetric('auth.tenant_role_success', 1, {
            role: tenantMembership.role,
            tenant_id: tenant.id,
          });
        } catch (error) {
          console.error('Tenant role validation error:', error);
          return forbiddenResponse(res, 'Role verification failed');
        }
      }

      // ============================================
      // 10b. Apply Tenant Scoping (Prisma Client Extension)
      // ============================================

      if (tenant && effectiveConfig.autoTenantScope) {

        // Create tenant-scoped Prisma client
        prisma = prisma.$extends(createTenantExtension(tenant.id, {
          // Optional: specify models explicitly for better performance
          // models: ['project', 'task', 'auditLog'],
          // Or let it auto-detect from schema (recommended)
        }));

        monitoring.recordMetric('tenant.scoping.applied', 1, {
          tenant_id: tenant.id,
        });
      }

      // ============================================
      // 11. Resource Ownership Verification
      // ============================================

      let resource: any = undefined;

      if (effectiveConfig.requireOwnership && user) {
        const { model, resourceIdParam, resourceIdField, ownerIdField, tenantIdField, selectFields } = effectiveConfig.requireOwnership;
        const resourceId = params[resourceIdParam];

        if (!resourceId) {
          return validationErrorResponse(res, `Missing required parameter: ${resourceIdParam}`);
        }

        // Validate model name to prevent SQL injection
        if (!validateModelName(model)) {
          console.error(`Invalid model name: ${model}`);
          return forbiddenResponse(res, 'Invalid resource type');
        }

        try {
          // Build Prisma query with ownership filters
          const where: any = {
            [resourceIdField || 'id']: resourceId,
          };

          // Add owner filter
          if (ownerIdField && user.id) {
            where[ownerIdField] = user.id;
          }

          // Add tenant filter
          if (tenantIdField && tenant?.id) {
            where[tenantIdField] = tenant.id;
          }

          // Query using validated model name
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
      // 12. Execute Handler with Timeout
      // ============================================

      const handlerContext: EnhancedHandlerContext<TInput> = {
        input,
        user,
        prisma,
        params,
        query,
        request: req,
        ...(resource ? { resource } : {}),
        ...(tenant ? { tenant } : {}),
        ...(idempotencyKey ? { idempotencyKey } : {}),
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
        // Transaction helper
        transaction: async <T>(fn: (tx: PrismaClient) => Promise<T>): Promise<T> => {
          return await prisma!.$transaction(async (tx: any) => {
            return await fn(tx as PrismaClient);
          });
        },
      };

      // Capture old data for UPDATE/DELETE operations (deep clone for audit trail)
      let oldData: any;
      if (auditEnabled && effectiveConfig.auditConfig?.trackDataChanges && resource) {
        oldData = deepClone(resource);
      }

      // Execute with timeout
      const timeout = effectiveConfig.timeout || DEFAULT_REQUEST_TIMEOUT;

      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Request timeout after ${timeout}ms`));
        }, timeout);
      });

      const result = await Promise.race([
        effectiveConfig.handler(handlerContext),
        timeoutPromise,
      ]);

      // ============================================
      // 13. Auto-sanitize and encrypt response
      // ============================================

      let processedResult = result;

      // Sanitize response
      const shouldSanitize = effectiveConfig.sanitizeResponse !== false;
      if (shouldSanitize) {
        const sanitizationService = SanitizationService.getInstance();
        processedResult = await sanitizationService.sanitizeResponse(processedResult);
        monitoring.recordMetric('sanitization.applied', 1);
      }

      // Encrypt sensitive fields if configured
      try {
        processedResult = await encryptionService.processResponse(processedResult);
        monitoring.recordMetric('encryption.applied', 1);
      } catch (error: any) {
        // In production, encryption failures should fail the request
        if (process.env.NODE_ENV === 'production') {
          console.error('Encryption failed:', sanitizeErrorMessage(error.message));
          throw new Error('Failed to secure response data');
        } else {
          console.warn('⚠️  Encryption service error (dev mode):', error.message);
        }
      }

      // ============================================
      // 14. Cache Result
      // ============================================

      if (effectiveConfig.cache && req.method === 'GET') {
        const cacheManager = CacheManager.getInstance();
        const cacheKey = effectiveConfig.cache.keyGenerator
          ? effectiveConfig.cache.keyGenerator(req, user || undefined)
          : generateCacheKey(req.path, input, user?.id, tenant?.id);

        try {
          await cacheManager.set(cacheKey, processedResult, effectiveConfig.cache.ttl);
          monitoring.recordMetric('cache.set', 1);
        } catch (error: any) {
          console.error('Cache set failed:', sanitizeErrorMessage(error.message));
          // Don't fail the request if caching fails
        }
      }

      // ============================================
      // 15. Store Idempotency Result
      // ============================================

      if (idempotencyKey) {
        try {
          await idempotencyService.set(idempotencyKey, {
            data: processedResult,
            statusCode: effectiveConfig.successStatus || 200,
          }, 86400); // 24 hours
          monitoring.recordMetric('idempotency.stored', 1);
        } catch (error: any) {
          console.error('Idempotency store failed:', sanitizeErrorMessage(error.message));
          // Don't fail the request if idempotency storage fails
        }
      }

      // ============================================
      // 16. Success Response
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
        const resourceType = effectiveConfig.auditConfig?.resourceType || effectiveConfig.requireOwnership?.model;
        const resourceId = effectiveConfig.requireOwnership?.resourceIdParam ? params[effectiveConfig.requireOwnership.resourceIdParam] : undefined;

        try {
          await auditService.logEvent(
            {
              eventType,
              category: effectiveConfig.auditConfig?.category as any || AuditCategory.DATA,
              action: effectiveConfig.auditConfig?.action || `${req.method.toLowerCase()}.${req.path}`,
              description: `${req.method} ${req.path}`,
              ...(resourceType ? { resourceType } : {}),
              ...(resourceId ? { resourceId } : {}),
              ...(effectiveConfig.auditConfig?.trackDataChanges ? { oldData } : {}),
              ...(effectiveConfig.auditConfig?.captureResponseBody ? { newData: processedResult } : {}),
              status: AuditStatus.SUCCESS,
              statusCode: effectiveConfig.successStatus || 200,
              severity: AuditSeverity.INFO,
              executionTimeMs: executionTime,
              ...(effectiveConfig.auditConfig?.metadata ? { metadata: effectiveConfig.auditConfig.metadata } : {}),
              ...(effectiveConfig.auditConfig?.tags ? { tags: effectiveConfig.auditConfig.tags } : {}),
              ...(effectiveConfig.auditConfig?.retentionCategory ? { retentionCategory: effectiveConfig.auditConfig.retentionCategory } : {}),
            },
            {
              user,
              ...(tenant ? { tenant } : {}),
              request: req,
              traceId,
            }
          );
        } catch (error: any) {
          console.error('Audit log failed:', sanitizeErrorMessage(error.message));
          // Don't fail the request if audit logging fails
        }
      }

      return successResponse(res, processedResult, undefined, effectiveConfig.successStatus, {
        executionTime,
        ...(rateLimitInfo ? { rateLimit: rateLimitInfo } : {}),
      });

    } catch (error: any) {
      const executionTime = Date.now() - startTime;

      // Sanitize error message for logging
      const sanitizedError = sanitizeErrorMessage(error.message);

      // Record error metrics
      if (monitoring) {
        monitoring.recordMetric('handler.error', 1, {
          method: req.method,
          path: req.path,
          error_type: error.constructor.name,
          execution_time: executionTime.toString(),
        });
      }

      console.error('[API Handler Error]', {
        method: req.method,
        url: req.url,
        error: sanitizedError,
        traceId,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      });

      // Audit: Log error
      if (auditEnabled && auditService) {
        const eventType = mapMethodToAuditEventType(req.method);
        try {
          await auditService.logEvent(
            {
              eventType,
              category: AuditCategory.SYSTEM,
              action: `${req.method.toLowerCase()}.error`,
              description: `Error in ${req.method} ${req.path}`,
              status: AuditStatus.FAILURE,
              errorMessage: sanitizedError,
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
        } catch (auditError: any) {
          console.error('Audit log error failed:', sanitizeErrorMessage(auditError.message));
        }
      }

      // Zod validation errors
      if (error instanceof z.ZodError) {
        return validationErrorResponse(
          res,
          'Validation failed',
          error.flatten().fieldErrors
        );
      }

      // Timeout errors
      if (error.message && error.message.includes('timeout')) {
        if (monitoring) {
          monitoring.recordMetric('handler.timeout', 1);
        }
        return errorResponse(res, 'REQUEST_TIMEOUT', 'Request timed out', 408);
      }

      // Return generic error (don't expose internal details)
      return internalErrorResponse(
        res,
        process.env.NODE_ENV === 'development'
          ? `Internal error: ${sanitizedError}`
          : 'An unexpected error occurred'
      );

    } finally {
      // Cleanup: Always end monitoring span
      if (span && monitoring) {
        try {
          monitoring.endSpan(span);
        } catch (error: any) {
          console.error('Failed to end monitoring span:', error.message);
        }
      }

      // Cleanup: Disconnect Prisma if needed
      // Note: In production, use connection pooling and don't disconnect on every request
      // Only disconnect tenant-specific clients that were created for this request
      if (prisma && tenant) {
        try {
          // Don't await - let it disconnect in background
          prisma.$disconnect().catch((error: any) => {
            console.error('Prisma disconnect error:', error.message);
          });
        } catch (error) {
          // Ignore disconnect errors in finally block
        }
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
 * SECURITY FEATURES:
 * - JWT/Session authentication required
 * - CSRF protection enabled by default
 * - Rate limiting per user
 * - Audit logging enabled
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
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth' | 'preset'>,
  injectedPrisma?: PrismaClient
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({
    preset: 'authenticated',
    ...config,
  }, injectedPrisma);
};

/**
 * Create a public handler (no authentication required)
 * 
 * SECURITY FEATURES:
 * - No authentication required
 * - CSRF protection disabled
 * - Rate limiting by IP address
 * - Audit logging for security events
 * 
 * Use when:
 * - The endpoint should be accessible without login
 * - Public data or resources are being served
 * - Authentication is optional or not needed
 * - The endpoint is part of a public API
 * 
 * Example: Public content, health checks, documentation endpoints, login/signup
 * 
 * IMPORTANT: Be extra careful with input validation on public endpoints!
 */
export const createPublicHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth' | 'preset'>,
  injectedPrisma?: PrismaClient
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({
    preset: 'public',
    ...config,
  }, injectedPrisma);
};

/**
 * Create a super admin-only handler
 * 
 * SECURITY FEATURES:
 * - Superadmin role required
 * - Enhanced audit logging
 * - Stricter rate limits
 * - CSRF protection required
 * - All operations logged with HIGH severity
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
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth' | 'allowedRoles'>,
  injectedPrisma?: PrismaClient
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({
    preset: 'admin',
    ...config,
  }, injectedPrisma);
};

/**
 * Create a tenant-scoped handler
 * 
 * SECURITY FEATURES:
 * - Tenant context required
 * - Automatic tenant-scoped queries (prevents cross-tenant data access)
 * - Tenant-role validation (prevents cross-tenant privilege escalation)
 * - Enhanced audit logging with tenant context
 * - Tenant-aware caching
 * 
 * Use when:
 * - The endpoint operates within a multi-tenant context
 * - Data should be automatically scoped to the user's tenant
 * - Tenant isolation is required
 * - The resource belongs to a specific tenant
 * 
 * Features enabled by default:
 * - Tenant-role validation (prevents cross-tenant role escalation)
 * - Auto-tenant scoping (automatically filters queries by tenant_id)
 * - Multi-tenancy feature flag
 * - CSRF protection
 * 
 * @param config - Handler configuration
 * @param effectiveConfig.allowedRoles - Optional tenant roles (e.g., ['OWNER', 'MANAGER'])
 * 
 * @example
 * // Any tenant member
 * createTenantHandler({ 
 *   handler: async (ctx) => { ... } 
 * })
 * 
 * // Only owners and managers
 * createTenantHandler({ 
 *   allowedRoles: ['OWNER', 'MANAGER'],
 *   handler: async (ctx) => { ... } 
 * })
 * 
 * // With transaction support
 * createTenantHandler({
 *   handler: async (ctx) => {
 *     return await ctx.transaction(async (tx) => {
 *       const user = await tx.user.create({ ... });
 *       const profile = await tx.profile.create({ ... });
 *       return { user, profile };
 *     });
 *   }
 * })
 */
export const createTenantHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth'>,
  injectedPrisma?: PrismaClient
): ReturnType<typeof _createHandler<TInput, TOutput>> => {
  return _createHandler({
    preset: 'tenant',
    ...config,
    // Allow overriding tenant-specific settings
    tenantRoleValidation: config.tenantRoleValidation !== false,
    autoTenantScope: config.autoTenantScope !== false,
  }, injectedPrisma);
};

// ============================================
// Export Types
// ============================================

export type {
  HandlerConfig,
  HandlerContext,
  EnhancedHandlerContext,
  User,
  TenantContext,
  RateLimitInfo,
  AllowedModel,
};
