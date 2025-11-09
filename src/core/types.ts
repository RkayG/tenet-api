/**
 * Comprehensive TypeScript types and interfaces for the Secure API Handler Framework
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

// ============================================
// Core User and Authentication Types
// ============================================

export interface User {
  id: string;
  email: string;
  brand_id: string;
  role?: string;
  permissions?: string[];
  tenant_id?: string;
  metadata?: Record<string, any>;
  last_login?: Date;
  is_active?: boolean;
}

export interface AuthToken {
  access_token: string;
  refresh_token?: string;
  token_type: 'Bearer';
  expires_in: number;
  expires_at: Date;
}

export interface AuthStrategy {
  name: string;
  authenticate(request: NextRequest): Promise<User | null>;
  refresh?(token: string): Promise<User | null>;
  validate?(token: string): Promise<boolean>;
}

// ============================================
// Handler Configuration Types
// ============================================

export interface HandlerConfig<TInput = unknown, TOutput = unknown> {
  /** Zod schema for input validation */
  schema?: z.ZodSchema<TInput>;

  /** Whether authentication is required */
  requireAuth?: boolean;

  /** Authentication strategies to use */
  authStrategies?: string[];

  /** Allowed user roles */
  allowedRoles?: string[];

  /** Required permissions */
  requiredPermissions?: string[];

  /** Automatic resource ownership verification */
  requireOwnership?: OwnershipConfig;

  /** Rate limiting configuration */
  rateLimit?: RateLimitConfig;

  /** Caching configuration */
  cache?: CacheConfig;

  /** Whether to automatically sanitize the response */
  sanitizeResponse?: boolean;

  /** API version requirements */
  apiVersion?: string;

  /** Custom success status code */
  successStatus?: number;

  /** Monitoring configuration */
  monitoring?: MonitoringConfig;

  /** Feature flags */
  featureFlags?: string[];

  /** The actual request handler */
  handler: (ctx: HandlerContext<TInput>) => Promise<TOutput>;
}

export interface OwnershipConfig {
  table: string;
  resourceIdParam: string;
  resourceIdColumn?: string;
  brandIdColumn?: string;
  tenantIdColumn?: string;
  selectColumns?: string;
  ownershipField?: string;
}

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (req: NextRequest, user?: User) => string;
  handler?: (req: NextRequest, res: NextResponse) => Promise<NextResponse>;
}

export interface CacheConfig {
  ttl: number;
  keyGenerator?: (req: NextRequest, user?: User) => string;
  condition?: (req: NextRequest, user?: User) => boolean;
  invalidateOn?: string[];
}

export interface MonitoringConfig {
  enableTracing?: boolean;
  enableMetrics?: boolean;
  customTags?: Record<string, string>;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

// ============================================
// Handler Context and Response Types
// ============================================

export interface HandlerContext<TInput = unknown> {
  /** Validated input data */
  input: TInput;

  /** Authenticated user */
  user: User | null;

  /** Supabase client instance */
  supabase: any; // SupabaseClient type

  /** URL parameters */
  params: Record<string, string>;

  /** Query string parameters */
  searchParams: URLSearchParams;

  /** Original Next.js request object */
  request: NextRequest;

  /** Verified resource data */
  resource?: any;

  /** Tenant context */
  tenant?: TenantContext;

  /** Request tracing information */
  trace?: TraceContext;

  /** Cache instance */
  cache?: any; // Redis type
}

export interface TenantContext {
  id: string;
  name: string;
  config: Record<string, any>;
  database?: string;
  schema?: string;
}

export interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  startTime: Date;
  tags: Record<string, string>;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: ApiError;
  meta?: ApiMeta;
}

export interface ApiError {
  code: ErrorCode;
  message: string;
  details?: Record<string, any>;
  traceId?: string;
}

export interface ApiMeta {
  timestamp: string;
  version: string;
  requestId: string;
  executionTime?: number;
}

export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'AUTHENTICATION_ERROR'
  | 'AUTHORIZATION_ERROR'
  | 'RESOURCE_NOT_FOUND'
  | 'RESOURCE_FORBIDDEN'
  | 'RATE_LIMIT_EXCEEDED'
  | 'INTERNAL_ERROR'
  | 'SERVICE_UNAVAILABLE'
  | 'BAD_REQUEST';

// ============================================
// Security and Sanitization Types
// ============================================

export interface SanitizationConfig {
  html?: HtmlSanitizationConfig;
  sql?: SqlSanitizationConfig;
  xss?: XssProtectionConfig;
  sensitive?: SensitiveDataConfig;
}

export interface HtmlSanitizationConfig {
  allowedTags?: string[];
  allowedAttributes?: Record<string, string[]>;
  selfClosing?: string[];
  allowComments?: boolean;
}

export interface SqlSanitizationConfig {
  allowedOperators?: string[];
  maxQueryLength?: number;
  preventInjection?: boolean;
}

export interface XssProtectionConfig {
  enabled: boolean;
  customPatterns?: RegExp[];
  escapeHtml?: boolean;
}

export interface SensitiveDataConfig {
  fields: string[];
  maskCharacter?: string;
  maskLength?: number;
  algorithms?: EncryptionAlgorithm[];
}

export type EncryptionAlgorithm = 'AES-256-GCM' | 'AES-256-CBC' | 'RSA-OAEP';

// ============================================
// Caching Types
// ============================================

export interface CacheEntry<T = any> {
  key: string;
  value: T;
  ttl: number;
  createdAt: Date;
  tags?: string[];
}

export interface CacheInvalidationRule {
  pattern: string;
  tags?: string[];
  condition?: (key: string, entry: CacheEntry) => boolean;
}

// ============================================
// Monitoring and Observability Types
// ============================================

export interface Metric {
  name: string;
  value: number;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  labels?: Record<string, string>;
  timestamp?: Date;
}

export interface TraceSpan {
  id: string;
  name: string;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  attributes: Record<string, any>;
  events: TraceEvent[];
  status?: 'ok' | 'error';
}

export interface TraceEvent {
  name: string;
  timestamp: Date;
  attributes: Record<string, any>;
}

export interface HealthCheck {
  name: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  message?: string;
  details?: Record<string, any>;
  timestamp: Date;
}

// ============================================
// Configuration Types
// ============================================

export interface AppConfig {
  environment: 'development' | 'staging' | 'production';
  port: number;
  host: string;

  // Database
  database: DatabaseConfig;

  // Authentication
  auth: AuthConfig;

  // Security
  security: SecurityConfig;

  // Caching
  cache: CacheProviderConfig;

  // Monitoring
  monitoring: MonitoringProviderConfig;

  // Multi-tenancy
  multitenancy: MultitenancyConfig;

  // Feature flags
  features: Record<string, boolean>;
}

export interface DatabaseConfig {
  url: string;
  poolSize: number;
  ssl: boolean;
  timeout: number;
}

export interface AuthConfig {
  jwt: {
    secret: string;
    expiresIn: string;
    refreshExpiresIn: string;
    issuer: string;
  };
  strategies: string[];
}

export interface SecurityConfig {
  encryption: {
    algorithm: EncryptionAlgorithm;
    key: string;
  };
  rateLimiting: {
    enabled: boolean;
    redisUrl?: string;
  };
  sanitization: SanitizationConfig;
}

export interface CacheProviderConfig {
  provider: 'redis' | 'memory' | 'none';
  redis?: RedisConfig;
  defaultTtl: number;
}

export interface RedisConfig {
  url: string;
  password?: string;
  database?: number;
}

export interface MonitoringProviderConfig {
  provider: 'datadog' | 'newrelic' | 'prometheus' | 'none';
  apiKey?: string;
  serviceName: string;
  environment: string;
}

export interface MultitenancyConfig {
  enabled: boolean;
  strategy: 'shared_schema' | 'separate_schema' | 'separate_database';
  tenantHeader: string;
  defaultTenant?: string;
}

// ============================================
// API Versioning Types
// ============================================

export interface ApiVersion {
  version: string;
  path: string;
  deprecated?: boolean;
  sunsetDate?: Date;
  changelog?: string[];
}

export interface VersionConfig {
  current: string;
  supported: string[];
  default: string;
  header: string;
  parameter: string;
}

// ============================================
// Utility Types
// ============================================

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type RequiredKeys<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type Prettify<T> = {
  [K in keyof T]: T[K];
} & {};

// ============================================
// Event Types for Extensibility
// ============================================

export interface FrameworkEvent {
  type: string;
  timestamp: Date;
  data: Record<string, any>;
  context?: HandlerContext;
}

export type FrameworkEventType =
  | 'handler:start'
  | 'handler:complete'
  | 'handler:error'
  | 'auth:success'
  | 'auth:failure'
  | 'cache:hit'
  | 'cache:miss'
  | 'rate_limit:exceeded'
  | 'sanitization:applied'
  | 'encryption:applied';
