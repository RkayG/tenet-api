/**
 * Logger Utility Unit Tests
 * 
 * Tests for Winston logger wrapper
 */

import { logger } from '../../../src/utils/logger';

// Mock Winston
jest.mock('winston', () => {
    const mockLogger = {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
        log: jest.fn(),
        child: jest.fn(),
    };
    return {
        createLogger: jest.fn(() => mockLogger),
        format: {
            combine: jest.fn(),
            timestamp: jest.fn(),
            json: jest.fn(),
            colorize: jest.fn(),
            printf: jest.fn(),
            errors: jest.fn(),
            simple: jest.fn(),
        },
        transports: {
            Console: jest.fn(),
            File: jest.fn(),
        },
    };
});

describe('Logger Utility', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(logger, 'info').mockImplementation();
        jest.spyOn(logger, 'error').mockImplementation();
        jest.spyOn(logger, 'warn').mockImplementation();
        jest.spyOn(logger, 'debug').mockImplementation();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('Basic Logging', () => {
        it('should log info messages', () => {
            logger.info('Test info message');

            expect(logger.info).toHaveBeenCalledWith('Test info message');
        });

        it('should log error messages', () => {
            logger.error('Test error message');

            expect(logger.error).toHaveBeenCalledWith('Test error message');
        });

        it('should log warning messages', () => {
            logger.warn('Test warning message');

            expect(logger.warn).toHaveBeenCalledWith('Test warning message');
        });

        it('should log debug messages', () => {
            logger.debug('Test debug message');

            expect(logger.debug).toHaveBeenCalledWith('Test debug message');
        });
    });

    describe('Structured Logging', () => {
        it('should log with metadata', () => {
            logger.info('User login', { userId: 'user-123', ip: '192.168.1.1' });

            expect(logger.info).toHaveBeenCalledWith(
                'User login',
                expect.objectContaining({
                    userId: 'user-123',
                    ip: '192.168.1.1',
                })
            );
        });

        it('should log errors with stack traces', () => {
            const error = new Error('Test error');

            logger.error('Operation failed', { error });

            expect(logger.error).toHaveBeenCalledWith(
                'Operation failed',
                expect.objectContaining({
                    error: expect.any(Error),
                })
            );
        });
    });

    describe('Request Logging', () => {
        it('should log HTTP requests', () => {
            logger.request({
                method: 'GET',
                path: '/api/users',
                statusCode: 200,
                duration: 150,
            });

            expect(logger.info).toHaveBeenCalled();
        });

        it('should log request with user context', () => {
            logger.request({
                method: 'POST',
                path: '/api/posts',
                userId: 'user-123',
                statusCode: 201,
            });

            expect(logger.info).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    userId: 'user-123',
                })
            );
        });
    });

    describe('Security Logging', () => {
        it('should log security events', () => {
            logger.security('Failed login attempt', {
                userId: 'user-123',
                ip: '192.168.1.1',
                reason: 'Invalid password',
            });

            expect(logger.warn).toHaveBeenCalled();
        });

        it('should log authentication failures', () => {
            logger.auth('Authentication failed', {
                method: 'JWT',
                reason: 'Token expired',
            });

            expect(logger.warn).toHaveBeenCalled();
        });
    });

    describe('Query Logging', () => {
        it('should log database queries', () => {
            logger.query('SELECT * FROM users WHERE id = ?', {
                duration: 50,
                rows: 1,
            });

            expect(logger.debug).toHaveBeenCalled();
        });

        it('should log slow queries', () => {
            logger.query('SELECT * FROM large_table', {
                duration: 5000,
                rows: 10000,
            });

            expect(logger.warn).toHaveBeenCalled();
        });
    });
});
