/**
 * CSRF Protection Service
 * 
 * Provides Cross-Site Request Forgery protection for state-changing operations
 */

import crypto from 'crypto';
import { CacheManager } from '../caching/manager';

export interface CSRFConfig {
    tokenLength?: number;
    tokenTTL?: number; // in seconds
    cookieName?: string;
    headerName?: string;
}

export class CSRFProtection {
    private static instance: CSRFProtection;
    private cacheManager: CacheManager;
    private config: Required<CSRFConfig>;

    private constructor(config?: CSRFConfig) {
        this.cacheManager = CacheManager.getInstance();
        this.config = {
            tokenLength: config?.tokenLength || 32,
            tokenTTL: config?.tokenTTL || 3600, // 1 hour
            cookieName: config?.cookieName || 'csrf-token',
            headerName: config?.headerName || 'X-CSRF-Token',
        };
    }

    public static getInstance(config?: CSRFConfig): CSRFProtection {
        if (!CSRFProtection.instance) {
            CSRFProtection.instance = new CSRFProtection(config);
        }
        return CSRFProtection.instance;
    }

    /**
     * Generate a new CSRF token for a user
     */
    public async generateToken(userId?: string): Promise<string> {
        const token = crypto.randomBytes(this.config.tokenLength).toString('hex');
        const key = this.getCacheKey(token);

        // Store token with user ID association
        await this.cacheManager.set(
            key,
            { userId: userId || 'anonymous', createdAt: Date.now() },
            this.config.tokenTTL
        );

        return token;
    }

    /**
     * Validate a CSRF token
     */
    public async validateToken(token: string, userId?: string): Promise<boolean> {
        if (!token) {
            return false;
        }

        const key = this.getCacheKey(token);
        const stored = await this.cacheManager.get(key);

        if (!stored) {
            return false;
        }

        // Verify user ID matches (if provided)
        if (userId && stored.userId !== userId && stored.userId !== 'anonymous') {
            return false;
        }

        return true;
    }

    /**
     * Invalidate a CSRF token (e.g., after use)
     */
    public async invalidateToken(token: string): Promise<void> {
        const key = this.getCacheKey(token);
        await this.cacheManager.delete(key);
    }

    /**
     * Refresh a CSRF token (extend TTL)
     */
    public async refreshToken(token: string): Promise<boolean> {
        const key = this.getCacheKey(token);
        const stored = await this.cacheManager.get(key);

        if (!stored) {
            return false;
        }

        // Extend TTL
        await this.cacheManager.set(key, stored, this.config.tokenTTL);
        return true;
    }

    private getCacheKey(token: string): string {
        return `csrf:${token}`;
    }
}
