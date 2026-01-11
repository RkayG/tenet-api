/**
 * Test Helper Utilities
 * 
 * Common mocks and utilities for unit tests
 */

import { Request, Response } from 'express';
import { User, TenantContext } from '../../src/core/types';

/**
 * Mock Express Request
 */
export const mockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
    body: {},
    query: {},
    params: {},
    headers: {},
    method: 'GET',
    path: '/test',
    url: '/test',
    ip: '127.0.0.1',
    user: null,
    get: function (name: string) {
        return (this as any).headers[name.toLowerCase()] || undefined;
    },
    header: function (name: string) {
        return (this as any).headers[name.toLowerCase()] || undefined;
    },
    ...overrides,
});

/**
 * Mock Express Response
 */
export const mockResponse = (): Partial<Response> => {
    const res: any = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    res.send = jest.fn().mockReturnValue(res);
    res.set = jest.fn().mockReturnValue(res);
    res.header = jest.fn().mockReturnValue(res);
    return res;
};

/**
 * Mock User
 */
export const mockUser = (overrides: Partial<User> = {}): User => ({
    id: 'user-123',
    email: 'test@example.com',
    role: 'user',
    tenant_id: 'tenant-123',
    permissions: [],
    is_active: true,
    ...overrides,
});

/**
 * Mock Tenant Context
 */
export const mockTenant = (overrides: Partial<TenantContext> = {}): TenantContext => ({
    id: 'tenant-123',
    name: 'Test Tenant',
    ...overrides,
});

/**
 * Mock JWT Token
 */
export const mockJWTToken = (payload: any = {}) => {
    const defaultPayload = {
        sub: 'user-123',
        email: 'test@example.com',
        role: 'user',
        tenant_id: 'tenant-123',
        ...payload,
    };

    // Simple base64 encoding for testing (not secure, just for mocking)
    return `mock.${Buffer.from(JSON.stringify(defaultPayload)).toString('base64')}.signature`;
};

/**
 * Wait for async operations
 */
export const waitFor = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Mock Prisma Client
 */
export const mockPrismaClient = () => ({
    $connect: jest.fn().mockResolvedValue(undefined),
    $disconnect: jest.fn().mockResolvedValue(undefined),
    $queryRaw: jest.fn(),
    user: {
        findUnique: jest.fn(),
        findMany: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
    },
    auditLog: {
        create: jest.fn(),
        findMany: jest.fn(),
    },
});

/**
 * Mock Redis Client
 */
export const mockRedisClient = () => ({
    connect: jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    get: jest.fn(),
    set: jest.fn(),
    setEx: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    ttl: jest.fn(),
    expire: jest.fn(),
    sAdd: jest.fn(),
    sRem: jest.fn(),
    sMembers: jest.fn(),
    mGet: jest.fn(),
    keys: jest.fn(),
    info: jest.fn(),
    on: jest.fn(),
});

/**
 * Mock Logger
 */
export const mockLogger = () => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    request: jest.fn(),
    response: jest.fn(),
    query: jest.fn(),
    auth: jest.fn(),
    security: jest.fn(),
});
