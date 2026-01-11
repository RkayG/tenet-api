/**
 * Jest Setup File
 * 
 * Global test configuration and mocks
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-key';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-characters';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL = 'redis://localhost:6379';

// Increase test timeout for integration tests
jest.setTimeout(10000);

// Mock console methods to reduce noise in tests
global.console = {
    ...console,
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
};

// Mock jsdom to prevent canvas dependency issues
jest.mock('jsdom', () => ({
    JSDOM: jest.fn().mockImplementation(() => ({
        window: {
            document: {
                createElement: jest.fn(),
            },
        },
    })),
}));

// Global test utilities
global.sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

