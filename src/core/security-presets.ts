/**
 * Security Presets for Handler Configuration
 * 
 * Pre-configured security settings for common use cases.
 * Simplifies handler configuration while maintaining flexibility.
 */

import { HandlerConfig } from './types';
import { AuditSeverity } from '../audit/audit-types';

/**
 * Pre-configured security presets for common use cases
 */
export const securityPresets = {
    /**
     * Public endpoints (no authentication)
     * 
     * Use for: Health checks, public content, login/signup
     * 
     * Features:
     * - No authentication required
     * - No CSRF protection
     * - Rate limiting by IP address
     * - Basic audit logging
     */
    public: {
        requireAuth: false,
        csrfProtection: false,
        rateLimit: {
            maxRequests: 100,
            windowMs: 60000,
            keyGenerator: (req: any) => req.ip || 'unknown',
        },
        auditConfig: {
            enabled: true,
            trackDataChanges: false,
        },
    },

    /**
     * Authenticated endpoints (requires login)
     * 
     * Use for: User profiles, settings, personal data
     * 
     * Features:
     * - JWT/Session authentication required
     * - CSRF protection enabled
     * - Rate limiting per user
     * - Full audit logging
     */
    authenticated: {
        requireAuth: true,
        csrfProtection: true,
        rateLimit: {
            maxRequests: 200,
            windowMs: 60000,
            keyGenerator: (req: any, user: any) => user?.id || req.ip || 'unknown',
        },
        auditConfig: {
            enabled: true,
            trackDataChanges: true,
        },
    },

    /**
     * Admin-only endpoints
     * 
     * Use for: System configuration, user management, admin operations
     * 
     * Features:
     * - Superadmin role required
     * - Enhanced CSRF protection
     * - Stricter rate limits
     * - High-severity audit logging
     */
    admin: {
        requireAuth: true,
        allowedRoles: ['superadmin'],
        csrfProtection: true,
        rateLimit: {
            maxRequests: 50,
            windowMs: 60000,
        },
        auditConfig: {
            enabled: true,
            trackDataChanges: true,
            severity: AuditSeverity.CRITICAL,
        },
    },

    /**
     * Tenant-scoped endpoints
     * 
     * Use for: Multi-tenant resources, organization data
     * 
     * Features:
     * - Authentication + tenant context required
     * - Automatic tenant scoping
     * - Tenant-role validation
     * - CSRF protection
     * - Tenant-aware caching
     */
    tenant: {
        requireAuth: true,
        featureFlags: ['multitenancy'],
        tenantRoleValidation: true,
        autoTenantScope: true,
        csrfProtection: true,
        auditConfig: {
            enabled: true,
            trackDataChanges: true,
        },
    },

    /**
     * Read-only endpoints (GET requests)
     * 
     * Use for: Data retrieval, reports, dashboards
     * 
     * Features:
     * - Authentication required
     * - No CSRF (GET only)
     * - Aggressive caching
     * - Lighter audit logging
     */
    readonly: {
        requireAuth: true,
        csrfProtection: false,
        cache: {
            ttl: 300, // 5 minutes
        },
        auditConfig: {
            enabled: true,
            trackDataChanges: false,
        },
    },

    /**
     * High-security endpoints (payments, sensitive operations)
     * 
     * Use for: Payments, financial transactions, sensitive data
     * 
     * Features:
     * - Authentication required
     * - CSRF + Idempotency required
     * - Strict rate limits
     * - Request timeouts
     * - Full audit trail with response capture
     */
    highSecurity: {
        requireAuth: true,
        csrfProtection: true,
        idempotency: true,
        timeout: 15000, // 15 seconds
        rateLimit: {
            maxRequests: 10,
            windowMs: 60000,
        },
        auditConfig: {
            enabled: true,
            trackDataChanges: true,
            captureResponseBody: true,
            severity: AuditSeverity.CRITICAL,
        },
    },
} as const;

export type SecurityPreset = keyof typeof securityPresets;

/**
 * Get a security preset by name
 */
export function getSecurityPreset(preset: SecurityPreset): Partial<HandlerConfig> {
    return securityPresets[preset] as Partial<HandlerConfig>;
}

/**
 * Merge a preset with user configuration
 * User configuration takes precedence over preset
 */
export function mergePresetConfig<TInput, TOutput>(
    preset: SecurityPreset,
    userConfig: HandlerConfig<TInput, TOutput>
): HandlerConfig<TInput, TOutput> {
    const presetConfig = getSecurityPreset(preset);

    return {
        ...presetConfig,
        ...userConfig,
        // Deep merge for nested objects
        auditConfig: {
            ...presetConfig.auditConfig,
            ...userConfig.auditConfig,
        },
        rateLimit: userConfig.rateLimit || presetConfig.rateLimit,
        cache: userConfig.cache || presetConfig.cache,
    } as HandlerConfig<TInput, TOutput>;
}
