/**
 * Idempotency Service
 * 
 * Provides idempotency support for state-changing operations
 * Prevents duplicate requests from being processed multiple times
 */

import { CacheManager } from '../caching/manager';

export interface IdempotencyResponse {
    data: any;
    statusCode: number;
}

export class IdempotencyService {
    private static instance: IdempotencyService;
    private cacheManager: CacheManager;

    private constructor() {
        this.cacheManager = CacheManager.getInstance();
    }

    public static getInstance(): IdempotencyService {
        if (!IdempotencyService.instance) {
            IdempotencyService.instance = new IdempotencyService();
        }
        return IdempotencyService.instance;
    }

    /**
     * Get cached response for an idempotency key
     */
    public async get(key: string): Promise<IdempotencyResponse | null> {
        const cacheKey = this.getCacheKey(key);
        const cached = await this.cacheManager.get(cacheKey);

        if (!cached) {
            return null;
        }

        return cached as IdempotencyResponse;
    }

    /**
     * Store response for an idempotency key
     */
    public async set(
        key: string,
        response: IdempotencyResponse,
        ttl: number = 86400 // 24 hours default
    ): Promise<void> {
        const cacheKey = this.getCacheKey(key);
        await this.cacheManager.set(cacheKey, response, ttl);
    }

    /**
     * Delete cached response for an idempotency key
     */
    public async delete(key: string): Promise<void> {
        const cacheKey = this.getCacheKey(key);
        await this.cacheManager.delete(cacheKey);
    }

    /**
     * Check if an idempotency key exists
     */
    public async exists(key: string): Promise<boolean> {
        const cacheKey = this.getCacheKey(key);
        return await this.cacheManager.exists(cacheKey);
    }

    private getCacheKey(key: string): string {
        return `idempotency:${key}`;
    }
}
