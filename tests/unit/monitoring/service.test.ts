/**
 * Monitoring Service Unit Tests
 * 
 * Tests for monitoring and metrics collection
 */

import { MonitoringService } from '../../../src/monitoring/service';

describe('Monitoring Service', () => {
    let monitoring: MonitoringService;

    beforeEach(() => {
        monitoring = MonitoringService.getInstance();
        jest.clearAllMocks();
    });

    describe('Span Management', () => {
        it('should create trace span and return spanId', () => {
            const spanId = monitoring.startSpan('test-operation', {
                userId: 'user-123',
            });

            expect(spanId).toBeDefined();
            expect(typeof spanId).toBe('string');
        });

        it('should end span successfully', () => {
            const spanId = monitoring.startSpan('test-operation');

            // Should not throw
            expect(() => {
                monitoring.endSpan(spanId, 'ok');
            }).not.toThrow();
        });

        it('should end span with error', () => {
            const spanId = monitoring.startSpan('test-operation');

            // Should not throw
            expect(() => {
                monitoring.endSpan(spanId, 'error', 'Test error');
            }).not.toThrow();
        });

        it('should track nested spans with parent context', () => {
            const parentSpanId = monitoring.startSpan('parent-operation');
            const childSpanId = monitoring.startSpan('child-operation', {}, {
                traceId: 'trace-123',
                spanId: parentSpanId,
            });

            expect(childSpanId).toBeDefined();
            expect(childSpanId).not.toBe(parentSpanId);
        });

        it('should add events to spans', () => {
            const spanId = monitoring.startSpan('test-operation');

            // Should not throw
            expect(() => {
                monitoring.addSpanEvent(spanId, 'test-event', { data: 'value' });
            }).not.toThrow();
        });
    });

    describe('Metrics Recording', () => {
        it('should record metric', () => {
            // Should not throw
            expect(() => {
                monitoring.recordMetric('api.requests', 1, { method: 'GET' });
            }).not.toThrow();
        });

        it('should record metric with labels', () => {
            monitoring.recordMetric('api.requests', 1, {
                method: 'GET',
                path: '/users',
            });

            const metrics = monitoring.getMetrics();
            expect(metrics.length).toBeGreaterThan(0);

            const lastMetric = metrics[metrics.length - 1];
            expect(lastMetric.name).toBe('api.requests');
            expect(lastMetric.value).toBe(1);
            expect(lastMetric.labels).toHaveProperty('method', 'GET');
            expect(lastMetric.labels).toHaveProperty('path', '/users');
        });

        it('should get recent metrics', () => {
            monitoring.recordMetric('test.metric', 100);
            monitoring.recordMetric('test.metric', 200);
            monitoring.recordMetric('test.metric', 300);

            const metrics = monitoring.getMetrics(2);
            expect(metrics.length).toBeLessThanOrEqual(2);
        });

        it('should include timestamp in metrics', () => {
            monitoring.recordMetric('test.metric', 42);

            const metrics = monitoring.getMetrics();
            const lastMetric = metrics[metrics.length - 1];

            expect(lastMetric.timestamp).toBeDefined();
            expect(lastMetric.timestamp).toBeInstanceOf(Date);
        });

        it('should infer metric type', () => {
            monitoring.recordMetric('api.requests', 1);
            monitoring.recordMetric('memory.usage', 1024);
            monitoring.recordMetric('response.time', 150);

            const metrics = monitoring.getMetrics(3);
            expect(metrics.length).toBeGreaterThan(0);

            // All metrics should have a type
            metrics.forEach(metric => {
                expect(metric.type).toBeDefined();
                expect(['counter', 'gauge', 'histogram', 'summary']).toContain(metric.type);
            });
        });
    });

    describe('Error Tracking', () => {
        it('should record error with Error object', () => {
            const error = new Error('Test error');
            error.name = 'TestError';

            // Should not throw
            expect(() => {
                monitoring.recordError(error);
            }).not.toThrow();
        });

        it('should record error with context', () => {
            const error = new Error('Database connection failed');
            error.name = 'DatabaseError';

            expect(() => {
                monitoring.recordError(error, {
                    database: 'postgres',
                    host: 'localhost',
                });
            }).not.toThrow();
        });

        it('should record error with span context', () => {
            const spanId = monitoring.startSpan('database-query');
            const error = new Error('Query timeout');

            expect(() => {
                monitoring.recordError(error, {}, spanId);
            }).not.toThrow();
        });

        it('should handle errors without message', () => {
            const error = new Error();
            error.name = 'UnknownError';

            expect(() => {
                monitoring.recordError(error);
            }).not.toThrow();
        });
    });

    describe('Health Checks', () => {
        it('should add health check', () => {
            const healthCheckFn = async () => ({
                name: 'database',
                status: 'healthy' as const,
                timestamp: new Date(),
            });

            expect(() => {
                monitoring.addHealthCheck('database', healthCheckFn);
            }).not.toThrow();
        });


        it('should get all health checks', () => {
            const checks = monitoring.getHealthChecks();
            expect(Array.isArray(checks)).toBe(true);
        });

        it('should get overall health status', () => {
            const health = monitoring.getOverallHealth();

            expect(health).toHaveProperty('name');
            expect(health).toHaveProperty('status');
            expect(health).toHaveProperty('timestamp');
            expect(['healthy', 'unhealthy', 'degraded']).toContain(health.status);
        });
    });

    describe('Active Spans', () => {
        it('should get active spans', () => {
            const spanId1 = monitoring.startSpan('operation-1');
            const spanId2 = monitoring.startSpan('operation-2');

            const activeSpans = monitoring.getActiveSpans();

            expect(Array.isArray(activeSpans)).toBe(true);
            expect(activeSpans.length).toBeGreaterThanOrEqual(0);
        });

        it('should remove span after ending', (done) => {
            const spanId = monitoring.startSpan('test-operation');
            monitoring.endSpan(spanId);

            // Span is removed after 100ms timeout
            setTimeout(() => {
                const activeSpans = monitoring.getActiveSpans();
                const hasSpan = activeSpans.some(span => span.id === spanId);
                expect(hasSpan).toBe(false);
                done();
            }, 150);
        });
    });

    describe('Service Configuration', () => {
        it('should create singleton instance', () => {
            const instance1 = MonitoringService.getInstance();
            const instance2 = MonitoringService.getInstance();

            expect(instance1).toBe(instance2);
        });

        it('should accept configuration', () => {
            const customMonitoring = MonitoringService.getInstance({
                serviceName: 'test-service',
                environment: 'test',
                provider: 'console',
            });

            expect(customMonitoring).toBeDefined();
        });
    });
});
