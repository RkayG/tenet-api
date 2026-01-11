/**
 * Validation Utility Unit Tests
 * 
 * Tests for validation helper functions
 */

import { z } from 'zod';
import { ValidationUtils } from '../../../src/utils/validation';

describe('Validation Utilities', () => {
    describe('Email Validation', () => {
        it('should validate correct email addresses', () => {
            expect(ValidationUtils.isValidEmail('test@example.com')).toBe(true);
            expect(ValidationUtils.isValidEmail('user.name@domain.co.uk')).toBe(true);
            expect(ValidationUtils.isValidEmail('user+tag@example.com')).toBe(true);
        });

        it('should reject invalid email addresses', () => {
            expect(ValidationUtils.isValidEmail('invalid')).toBe(false);
            expect(ValidationUtils.isValidEmail('missing@domain')).toBe(false);
            expect(ValidationUtils.isValidEmail('@example.com')).toBe(false);
            expect(ValidationUtils.isValidEmail('user@')).toBe(false);
        });
    });

    describe('Password Validation', () => {
        it('should validate strong passwords', () => {
            const result1 = ValidationUtils.validatePasswordStrength('StrongP@ss123');
            const result2 = ValidationUtils.validatePasswordStrength('C0mpl3x!Pass');

            expect(result1.isValid).toBe(true);
            expect(result2.isValid).toBe(true);
        });

        it('should reject weak passwords', () => {
            const result1 = ValidationUtils.validatePasswordStrength('weak');
            const result2 = ValidationUtils.validatePasswordStrength('nospecialchar123');
            const result3 = ValidationUtils.validatePasswordStrength('WeakItIs'); // Score 3 (Len, Upper, Lower)

            expect(result1.isValid).toBe(false);
            expect(result2.isValid).toBe(false);
            expect(result3.isValid).toBe(false);
        });

        it('should provide feedback for weak passwords', () => {
            const result = ValidationUtils.validatePasswordStrength('weak');

            expect(result.feedback.length).toBeGreaterThan(0);
            expect(result.score).toBeLessThan(4);
        });

        it('should enforce minimum length', () => {
            const result1 = ValidationUtils.validatePasswordStrength('Short1!');
            const result2 = ValidationUtils.validatePasswordStrength('LongEnough1!');

            expect(result1.isValid).toBe(false);
            expect(result2.isValid).toBe(true);
        });
    });

    describe('UUID Validation', () => {
        it('should validate correct UUIDs', () => {
            expect(ValidationUtils.isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
            expect(ValidationUtils.isValidUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
        });

        it('should reject invalid UUIDs', () => {
            expect(ValidationUtils.isValidUUID('invalid-uuid')).toBe(false);
            expect(ValidationUtils.isValidUUID('123')).toBe(false);
            expect(ValidationUtils.isValidUUID('')).toBe(false);
        });
    });

    describe('CUID Validation', () => {
        it('should validate correct CUIDs', () => {
            expect(ValidationUtils.isValidCUID('cjld2cjxh0000qzrmn831i7rn')).toBe(true);
        });

        it('should reject invalid CUIDs', () => {
            expect(ValidationUtils.isValidCUID('invalid-cuid')).toBe(false);
            expect(ValidationUtils.isValidCUID('123')).toBe(false);
        });
    });

    describe('URL Validation', () => {
        it('should validate correct URLs', () => {
            expect(ValidationUtils.isValidUrl('https://example.com')).toBe(true);
            expect(ValidationUtils.isValidUrl('http://subdomain.example.com/path')).toBe(true);
            expect(ValidationUtils.isValidUrl('https://example.com:8080/path?query=value')).toBe(true);
        });

        it('should reject invalid URLs', () => {
            expect(ValidationUtils.isValidUrl('not-a-url')).toBe(false);
            expect(ValidationUtils.isValidUrl('//example.com')).toBe(false);
        });
    });

    describe('Phone Number Validation', () => {
        it('should validate correct phone numbers', () => {
            expect(ValidationUtils.isValidPhoneNumber('+1234567890')).toBe(true);
            expect(ValidationUtils.isValidPhoneNumber('+442012345678')).toBe(true);
        });

        it('should reject invalid phone numbers', () => {
            expect(ValidationUtils.isValidPhoneNumber('abc')).toBe(false);
            expect(ValidationUtils.isValidPhoneNumber('invalid')).toBe(false);
        });
    });

    describe('IP Address Validation', () => {
        it('should validate IPv4 addresses', () => {
            expect(ValidationUtils.isValidIP('192.168.1.1')).toBe(true);
            expect(ValidationUtils.isValidIP('10.0.0.1')).toBe(true);
            expect(ValidationUtils.isValidIP('255.255.255.255')).toBe(true);
        });

        it('should validate IPv6 addresses', () => {
            expect(ValidationUtils.isValidIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
        });

        it('should reject invalid IP addresses', () => {
            expect(ValidationUtils.isValidIP('256.1.1.1')).toBe(false);
            expect(ValidationUtils.isValidIP('invalid')).toBe(false);
            expect(ValidationUtils.isValidIP('192.168.1')).toBe(false);
        });
    });

    describe('Credit Card Validation', () => {
        it('should validate correct credit card numbers', () => {
            expect(ValidationUtils.isValidCreditCard('4111111111111111')).toBe(true); // Visa test number
        });

        it('should reject invalid credit card numbers', () => {
            expect(ValidationUtils.isValidCreditCard('1234567890123456')).toBe(false);
            expect(ValidationUtils.isValidCreditCard('invalid')).toBe(false);
        });
    });

    describe('JSON Validation', () => {
        it('should validate correct JSON', () => {
            expect(ValidationUtils.isValidJSON('{"name":"John"}')).toBe(true);
            expect(ValidationUtils.isValidJSON('[1,2,3]')).toBe(true);
        });

        it('should reject invalid JSON', () => {
            expect(ValidationUtils.isValidJSON('invalid')).toBe(false);
            expect(ValidationUtils.isValidJSON('{name:John}')).toBe(false);
        });
    });

    describe('Date Validation', () => {
        it('should validate correct dates', () => {
            expect(ValidationUtils.isValidDate('2024-01-01')).toBe(true);
            expect(ValidationUtils.isValidDate('2024-01-01T12:00:00Z')).toBe(true);
        });

        it('should reject invalid dates', () => {
            expect(ValidationUtils.isValidDate('invalid')).toBe(false);
            expect(ValidationUtils.isValidDate('2024-13-01')).toBe(false);
        });
    });

    describe('ISO 8601 Validation', () => {
        it('should validate ISO 8601 dates', () => {
            expect(ValidationUtils.isValidISO8601('2024-01-01T12:00:00Z')).toBe(true);
            expect(ValidationUtils.isValidISO8601('2024-01-01T12:00:00.123Z')).toBe(true);
        });

        it('should reject non-ISO 8601 dates', () => {
            expect(ValidationUtils.isValidISO8601('2024-01-01')).toBe(false);
            expect(ValidationUtils.isValidISO8601('invalid')).toBe(false);
        });
    });

    describe('Slug Validation', () => {
        it('should validate correct slugs', () => {
            expect(ValidationUtils.isValidSlug('my-blog-post')).toBe(true);
            expect(ValidationUtils.isValidSlug('hello-world-123')).toBe(true);
        });

        it('should reject invalid slugs', () => {
            expect(ValidationUtils.isValidSlug('Invalid Slug')).toBe(false);
            expect(ValidationUtils.isValidSlug('slug_with_underscore')).toBe(false);
        });
    });

    describe('Hex Color Validation', () => {
        it('should validate correct hex colors', () => {
            expect(ValidationUtils.isValidHexColor('#FF0000')).toBe(true);
            expect(ValidationUtils.isValidHexColor('#F00')).toBe(true);
        });

        it('should reject invalid hex colors', () => {
            expect(ValidationUtils.isValidHexColor('FF0000')).toBe(false);
            expect(ValidationUtils.isValidHexColor('#GGGGGG')).toBe(false);
        });
    });

    describe('Security Checks', () => {
        it('should detect SQL injection patterns', () => {
            expect(ValidationUtils.containsSQLInjection("'; DROP TABLE users; --")).toBe(true);
            expect(ValidationUtils.containsSQLInjection("admin' OR '1'='1")).toBe(true);
            expect(ValidationUtils.containsSQLInjection("normal text")).toBe(false);
        });

        it('should detect XSS patterns', () => {
            expect(ValidationUtils.containsXSS('<script>alert(1)</script>')).toBe(true);
            expect(ValidationUtils.containsXSS('<img src=x onerror=alert(1)>')).toBe(true);
            expect(ValidationUtils.containsXSS('normal text')).toBe(false);
        });
    });

    describe('String Utilities', () => {
        it('should normalize strings', () => {
            expect(ValidationUtils.normalize('  Hello World  ')).toBe('hello world');
            expect(ValidationUtils.normalize('UPPERCASE')).toBe('uppercase');
        });

        it('should truncate strings', () => {
            expect(ValidationUtils.truncate('Long text here', 10)).toBe('Long te...');
            expect(ValidationUtils.truncate('Short', 10)).toBe('Short');
        });

        it('should check if string is empty', () => {
            expect(ValidationUtils.isEmpty('')).toBe(true);
            expect(ValidationUtils.isEmpty('   ')).toBe(true);
            expect(ValidationUtils.isEmpty('text')).toBe(false);
        });
    });

    describe('Zod Schema Validation', () => {
        it('should validate with Zod schemas', () => {
            const schema = z.object({
                name: z.string(),
                age: z.number().min(0).max(120),
            });

            const validData = { name: 'John', age: 30 };
            const result = ValidationUtils.validateWithSchema(schema, validData);

            expect(result.success).toBe(true);
            expect(result.data).toEqual(validData);
        });

        it('should return validation errors', () => {
            const schema = z.object({
                email: z.string().email(),
                age: z.number(),
            });

            const invalidData = { email: 'invalid', age: 'not-a-number' };
            const result = ValidationUtils.validateWithSchema(schema, invalidData);

            expect(result.success).toBe(false);
            expect(result.errors).toBeDefined();
        });
    });

    describe('File Validation', () => {
        it('should validate file extensions', () => {
            expect(ValidationUtils.isValidFileExtension('document.pdf', ['pdf', 'doc'])).toBe(true);
            expect(ValidationUtils.isValidFileExtension('image.jpg', ['png', 'gif'])).toBe(false);
        });

        it('should validate file sizes', () => {
            expect(ValidationUtils.isValidFileSize(1024 * 1024, 5)).toBe(true); // 1MB < 5MB
            expect(ValidationUtils.isValidFileSize(10 * 1024 * 1024, 5)).toBe(false); // 10MB > 5MB
        });

        it('should validate MIME types', () => {
            expect(ValidationUtils.isValidMimeType('image/jpeg', ['image/jpeg', 'image/png'])).toBe(true);
            expect(ValidationUtils.isValidMimeType('application/pdf', ['image/jpeg'])).toBe(false);
        });
    });

    describe('HTML Sanitization', () => {
        it('should sanitize HTML', () => {
            const result = ValidationUtils.sanitizeHTML('<script>alert(1)</script>');
            expect(result).not.toContain('<script>');
            expect(result).toContain('&lt;');
        });

        it('should escape special characters', () => {
            const result = ValidationUtils.sanitizeHTML('Test & "quotes"');
            expect(result).toContain('&amp;');
            expect(result).toContain('&quot;');
        });
    });
});
