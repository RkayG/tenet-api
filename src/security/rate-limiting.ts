/**
 * Rate Limiting Service
 *
 * Provides distributed rate limiting using Redis with sliding window algorithm
 */

import { createClient, RedisClientType } from 'redis';
import { RateLimitConfig } from '../core/types';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: Date;
  totalRequests: number;
}

export interface RateLimitEntry {
  count: number;
  windowStart: number;
}

export class RedisRateLimiter {
  private static instance: RedisRateLimiter;
  private redis: RedisClientType;
  private isConnected: boolean = false;

  private constructor() {
    this.redis = createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      password: process.env.REDIS_PASSWORD,
    });

    this.redis.on('error', (err) => {
      console.error('Redis connection error:', err);
      this.isConnected = false;
    });

    this.redis.on('connect', () => {
      console.log('Connected to Redis for rate limiting');
      this.isConnected = true;
    });
  }

  public static getInstance(): RedisRateLimiter {
    if (!RedisRateLimiter.instance) {
      RedisRateLimiter.instance = new RedisRateLimiter();
    }
    return RedisRateLimiter.instance;
  }

  /**
   * Check if request is within rate limit
   */
  public async checkLimit(key: string, config: RateLimitConfig): Promise<boolean> {
    if (!this.isConnected) {
      // Fallback to in-memory limiting if Redis is unavailable
      return this.checkMemoryLimit(key, config);
    }

    try {
      const now = Date.now();
      const windowMs = config.windowMs;
      const maxRequests = config.maxRequests;

      // Use Redis sorted set for sliding window
      const windowKey = `ratelimit:${key}`;
      const member = `${now}:${Math.random()}`;

      // Add current request to the window
      await this.redis.zadd(windowKey, now, member);

      // Remove requests outside the current window
      const windowStart = now - windowMs;
      await this.redis.zremrangebyscore(windowKey, 0, windowStart);

      // Count requests in current window
      const requestCount = await this.redis.zcount(windowKey, windowStart, now);

      // Set expiration on the key (cleanup)
      await this.redis.expire(windowKey, Math.ceil(windowMs / 1000) * 2);

      return requestCount <= maxRequests;
    } catch (error) {
      console.error('Rate limiting error:', error);
      // Allow request on error to avoid blocking legitimate traffic
      return true;
    }
  }

  /**
   * Get detailed rate limit information
   */
  public async getLimitInfo(key: string, config: RateLimitConfig): Promise<RateLimitResult> {
    if (!this.isConnected) {
      return this.getMemoryLimitInfo(key, config);
    }

    try {
      const now = Date.now();
      const windowMs = config.windowMs;
      const maxRequests = config.maxRequests;
      const windowKey = `ratelimit:${key}`;

      // Clean old entries
      const windowStart = now - windowMs;
      await this.redis.zremrangebyscore(windowKey, 0, windowStart);

      // Get current count
      const requestCount = await this.redis.zcount(windowKey, windowStart, now);

      // Calculate reset time
      const oldestRequest = await this.redis.zrange(windowKey, 0, 0, 'WITHSCORES');
      const resetTime = oldestRequest.length > 0
        ? new Date(parseInt(oldestRequest[1]) + windowMs)
        : new Date(now + windowMs);

      return {
        allowed: requestCount < maxRequests,
        remaining: Math.max(0, maxRequests - requestCount),
        resetTime,
        totalRequests: requestCount,
      };
    } catch (error) {
      console.error('Rate limit info error:', error);
      return {
        allowed: true,
        remaining: config.maxRequests,
        resetTime: new Date(Date.now() + config.windowMs),
        totalRequests: 0,
      };
    }
  }

  /**
   * Reset rate limit for a key
   */
  public async resetLimit(key: string): Promise<void> {
    if (!this.isConnected) {
      this.resetMemoryLimit(key);
      return;
    }

    try {
      const windowKey = `ratelimit:${key}`;
      await this.redis.del(windowKey);
    } catch (error) {
      console.error('Rate limit reset error:', error);
    }
  }

  /**
   * In-memory fallback rate limiting
   */
  private memoryStore = new Map<string, RateLimitEntry>();

  private checkMemoryLimit(key: string, config: RateLimitConfig): boolean {
    const now = Date.now();
    const entry = this.memoryStore.get(key);

    if (!entry) {
      this.memoryStore.set(key, { count: 1, windowStart: now });
      return true;
    }

    // Reset window if expired
    if (now - entry.windowStart >= config.windowMs) {
      this.memoryStore.set(key, { count: 1, windowStart: now });
      return true;
    }

    // Check if under limit
    if (entry.count < config.maxRequests) {
      entry.count++;
      return true;
    }

    return false;
  }

  private getMemoryLimitInfo(key: string, config: RateLimitConfig): RateLimitResult {
    const now = Date.now();
    const entry = this.memoryStore.get(key);

    if (!entry) {
      return {
        allowed: true,
        remaining: config.maxRequests - 1,
        resetTime: new Date(now + config.windowMs),
        totalRequests: 0,
      };
    }

    const isExpired = now - entry.windowStart >= config.windowMs;
    const currentCount = isExpired ? 0 : entry.count;

    return {
      allowed: currentCount < config.maxRequests,
      remaining: Math.max(0, config.maxRequests - currentCount),
      resetTime: new Date((isExpired ? now : entry.windowStart) + config.windowMs),
      totalRequests: currentCount,
    };
  }

  private resetMemoryLimit(key: string): void {
    this.memoryStore.delete(key);
  }

  /**
   * Clean up expired entries from memory store
   */
  public cleanupMemoryStore(): void {
    const now = Date.now();
    for (const [key, entry] of this.memoryStore.entries()) {
      if (now - entry.windowStart >= 3600000) { // 1 hour
        this.memoryStore.delete(key);
      }
    }
  }

  /**
   * Get rate limiting statistics
   */
  public async getStats(): Promise<{
    redisConnected: boolean;
    memoryStoreSize: number;
    redisInfo?: any;
  }> {
    const stats = {
      redisConnected: this.isConnected,
      memoryStoreSize: this.memoryStore.size,
    };

    if (this.isConnected) {
      try {
        const info = await this.redis.info();
        (stats as any).redisInfo = this.parseRedisInfo(info);
      } catch (error) {
        console.error('Failed to get Redis stats:', error);
      }
    }

    return stats;
  }

  private parseRedisInfo(info: string): Record<string, any> {
    const lines = info.split('\r\n');
    const parsed: Record<string, any> = {};

    for (const line of lines) {
      if (line.includes(':')) {
        const [key, value] = line.split(':');
        parsed[key] = value;
      }
    }

    return parsed;
  }

  /**
   * Connect to Redis
   */
  public async connect(): Promise<void> {
    if (!this.isConnected) {
      await this.redis.connect();
    }
  }

  /**
   * Disconnect from Redis
   */
  public async disconnect(): Promise<void> {
    if (this.isConnected) {
      await this.redis.disconnect();
    }
  }
}

export class MemoryRateLimiter {
  private static instance: MemoryRateLimiter;
  private store = new Map<string, { count: number; resetTime: number }>();

  private constructor() {}

  public static getInstance(): MemoryRateLimiter {
    if (!MemoryRateLimiter.instance) {
      MemoryRateLimiter.instance = new MemoryRateLimiter();
    }
    return MemoryRateLimiter.instance;
  }

  public async checkLimit(key: string, config: RateLimitConfig): Promise<boolean> {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now > entry.resetTime) {
      // Start new window
      this.store.set(key, {
        count: 1,
        resetTime: now + config.windowMs,
      });
      return true;
    }

    if (entry.count < config.maxRequests) {
      entry.count++;
      return true;
    }

    return false;
  }

  public async getLimitInfo(key: string, config: RateLimitConfig): Promise<RateLimitResult> {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now > entry.resetTime) {
      return {
        allowed: true,
        remaining: config.maxRequests,
        resetTime: new Date(now + config.windowMs),
        totalRequests: 0,
      };
    }

    return {
      allowed: entry.count < config.maxRequests,
      remaining: Math.max(0, config.maxRequests - entry.count),
      resetTime: new Date(entry.resetTime),
      totalRequests: entry.count,
    };
  }

  public async resetLimit(key: string): Promise<void> {
    this.store.delete(key);
  }
}
