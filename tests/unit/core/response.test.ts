/**
 * Response Utility Unit Tests
 * 
 * Tests for standardized API response functions
 */

import { mockResponse } from '../../utils/test-helpers';
import {
    successResponse,
    errorResponse,
    validationErrorResponse,
    unauthorizedResponse,
    forbiddenResponse,
    notFoundResponse,
    rateLimitResponse,
    internalErrorResponse,
    healthCheckResponse,
} from '../../../src/core/response';

describe('Response Utilities', () => {
    let res: any;

    beforeEach(() => {
        res = mockResponse();
    });

    describe('successResponse', () => {
        it('should return success response with data', () => {
            const data = { id: '123', name: 'Test' };

            successResponse(res, data);

            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: true,
                    data,
                    meta: expect.objectContaining({
                        timestamp: expect.any(String),
                        version: expect.any(String),
                        requestId: expect.any(String),
                    }),
                })
            );
        });

        it('should accept custom status code', () => {
            successResponse(res, { message: 'created' }, undefined, 201);

            expect(res.status).toHaveBeenCalledWith(201);
        });

        it('should include custom meta data', () => {
            const meta = { page: 1, limit: 10 };

            successResponse(res, { items: [] }, undefined, 200, meta);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    meta: expect.objectContaining(meta),
                })
            );
        });
    });

    describe('errorResponse', () => {
        it('should return error response', () => {
            errorResponse(res, 'ERROR_CODE', 'Error message', 500);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: false,
                    error: {
                        code: 'ERROR_CODE',
                        message: 'Error message',
                    },
                })
            );
        });

        it('should include error details', () => {
            const details = { field: 'email', issue: 'invalid format' };

            errorResponse(res, 'VALIDATION_ERROR', 'Validation failed', 400, details);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        details,
                    }),
                })
            );
        });

        it('should include trace ID', () => {
            const traceId = 'trace-123';

            errorResponse(res, 'ERROR', 'Error', 500, undefined, traceId);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        traceId,
                    }),
                })
            );
        });
    });

    describe('validationErrorResponse', () => {
        it('should return validation error', () => {
            const errors = {
                email: ['Invalid email format'],
                password: ['Password too short'],
            };

            validationErrorResponse(res, 'Validation failed', errors);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    success: false,
                    error: expect.objectContaining({
                        code: 'VALIDATION_ERROR',
                        message: 'Validation failed',
                        details: errors,
                    }),
                })
            );
        });
    });

    describe('unauthorizedResponse', () => {
        it('should return 401 unauthorized', () => {
            unauthorizedResponse(res);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        code: 'AUTHENTICATION_ERROR',
                    }),
                })
            );
        });

        it('should accept custom message', () => {
            unauthorizedResponse(res, 'Invalid token');

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        message: 'Invalid token',
                    }),
                })
            );
        });
    });

    describe('forbiddenResponse', () => {
        it('should return 403 forbidden', () => {
            forbiddenResponse(res);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        code: 'AUTHORIZATION_ERROR',
                    }),
                })
            );
        });
    });

    describe('notFoundResponse', () => {
        it('should return 404 not found', () => {
            notFoundResponse(res);

            expect(res.status).toHaveBeenCalledWith(404);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        code: 'RESOURCE_NOT_FOUND',
                    }),
                })
            );
        });
    });

    describe('rateLimitResponse', () => {
        it('should return 429 rate limit exceeded', () => {
            rateLimitResponse(res);

            expect(res.status).toHaveBeenCalledWith(429);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        code: 'RATE_LIMIT_EXCEEDED',
                    }),
                })
            );
        });
    });

    describe('internalErrorResponse', () => {
        it('should return 500 internal error', () => {
            internalErrorResponse(res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.objectContaining({
                        code: 'INTERNAL_ERROR',
                    }),
                })
            );
        });
    });

    describe('healthCheckResponse', () => {
        it('should return healthy status', () => {
            healthCheckResponse(res, 'healthy', {});

            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    status: 'healthy',
                })
            );
        });

        it('should return degraded status with 503', () => {
            healthCheckResponse(res, 'degraded', {});

            expect(res.status).toHaveBeenCalledWith(503);
        });

        it('should return unhealthy status with 503', () => {
            healthCheckResponse(res, 'unhealthy', {});

            expect(res.status).toHaveBeenCalledWith(503);
        });
    });
});
