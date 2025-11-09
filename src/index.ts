/**
 * Secure API Handler Framework
 *
 * A comprehensive framework for building secure, multi-tenant API handlers
 * with authentication, sanitization, encryption, rate limiting, caching,
 * and observability features.
 *
 * @packageDocumentation
 */

// Core framework
export { createHandler } from './core/handler';
export { createAuthenticatedHandler } from './core/handler';
export { createPublicHandler } from './core/handler';
export { createAdminHandler } from './core/handler';

// Types and interfaces
export type {
  HandlerConfig,
  HandlerContext,
  User,
  AuthToken,
  ApiResponse,
  ApiError,
  TenantContext,
  TraceContext,
  SanitizationConfig,
  CacheConfig,
  RateLimitConfig,
  MonitoringConfig,
  AppConfig,
  ApiVersion,
  FrameworkEvent,
  ErrorCode,
} from './core/types';

// Authentication
export { JWTStrategy } from './auth/strategies/jwt';
export { APIKeyStrategy } from './auth/strategies/api-key';
export { OAuthStrategy } from './auth/strategies/oauth';
export { AuthManager } from './auth/manager';

// Security
export { SanitizationService } from './security/sanitization';
export { EncryptionService } from './security/encryption';
export { SecurityHeaders } from './security/headers';

// Rate limiting
export { RedisRateLimiter } from './security/rate-limiting';
export { MemoryRateLimiter } from './security/rate-limiting';

// Caching
export { RedisCache } from './caching/redis';
export { MemoryCache } from './caching/memory';
export { CacheManager } from './caching/manager';

// Monitoring & Observability
export { MonitoringService } from './monitoring/service';
export { HealthChecker } from './monitoring/health';
export { Tracer } from './monitoring/tracer';

// Multi-tenancy
export { TenantManager } from './multitenancy/manager';
export { SharedSchemaStrategy } from './multitenancy/strategies/shared-schema';
export { SeparateSchemaStrategy } from './multitenancy/strategies/separate-schema';
export { SeparateDatabaseStrategy } from './multitenancy/strategies/separate-database';

// API Versioning
export { VersionManager } from './versioning/manager';
export { UrlVersioningStrategy } from './versioning/strategies/url';
export { HeaderVersioningStrategy } from './versioning/strategies/header';

// Configuration
export { ConfigManager } from './config/manager';
export { EnvironmentConfig } from './config/providers/environment';
export { FeatureFlags } from './config/feature-flags';

// Database
export { DatabaseManager } from './database/manager';
export { ConnectionPool } from './database/pool';

// Utilities
export { Logger } from './utils/logger';
export { ValidationUtils } from './utils/validation';
export { CryptoUtils } from './utils/crypto';
export { DateUtils } from './utils/date';

// Response helpers
export {
  successResponse,
  errorResponse,
  validationErrorResponse,
  unauthorizedResponse,
  forbiddenResponse,
  internalErrorResponse,
} from './core/response';

// Re-export commonly used external dependencies for convenience
export { z } from 'zod';
