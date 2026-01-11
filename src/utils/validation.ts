/**
 * Validation Utilities
 * 
 * Common validation functions for input sanitization and verification
 */

import { z } from 'zod';

export class ValidationUtils {
  /**
   * Validate email address
   */
  public static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate URL
   */
  public static isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Validate UUID
   */
  public static isValidUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }

  /**
   * Validate CUID
   */
  public static isValidCUID(cuid: string): boolean {
    const cuidRegex = /^c[a-z0-9]{24}$/;
    return cuidRegex.test(cuid);
  }

  /**
   * Validate phone number (international format)
   */
  public static isValidPhoneNumber(phone: string): boolean {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    return phoneRegex.test(phone.replace(/[\s()-]/g, ''));
  }

  /**
   * Validate password strength
   */
  public static validatePasswordStrength(password: string): {
    isValid: boolean;
    score: number;
    feedback: string[];
  } {
    const feedback: string[] = [];
    let score = 0;

    // Minimum length
    if (password.length < 8) {
      feedback.push('Password must be at least 8 characters long');
    } else {
      score++;
    }

    // Contains lowercase
    if (/[a-z]/.test(password)) {
      score++;
    } else {
      feedback.push('Password must contain lowercase letters');
    }

    // Contains uppercase
    if (/[A-Z]/.test(password)) {
      score++;
    } else {
      feedback.push('Password must contain uppercase letters');
    }

    // Contains numbers
    if (/\d/.test(password)) {
      score++;
    } else {
      feedback.push('Password must contain numbers');
    }

    // Contains special characters
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      score++;
    } else {
      feedback.push('Password must contain special characters');
    }

    return {
      isValid: score >= 4 && password.length >= 8,
      score,
      feedback,
    };
  }

  /**
   * Validate credit card number (Luhn algorithm)
   */
  public static isValidCreditCard(cardNumber: string): boolean {
    const cleaned = cardNumber.replace(/\s/g, '');

    if (!/^\d+$/.test(cleaned)) {
      return false;
    }

    let sum = 0;
    let isEven = false;

    for (let i = cleaned.length - 1; i >= 0; i--) {
      let digit = parseInt(cleaned[i]!);

      if (isEven) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }

      sum += digit;
      isEven = !isEven;
    }

    return sum % 10 === 0;
  }

  /**
   * Validate IP address (v4 or v6)
   */
  public static isValidIP(ip: string): boolean {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$/i;

    if (ipv4Regex.test(ip)) {
      const parts = ip.split('.');
      return parts.every(part => parseInt(part) <= 255);
    }

    return ipv6Regex.test(ip);
  }

  /**
   * Validate JSON string
   */
  public static isValidJSON(str: string): boolean {
    try {
      JSON.parse(str);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Validate date string
   */
  public static isValidDate(dateStr: string): boolean {
    const date = new Date(dateStr);
    return !isNaN(date.getTime());
  }

  /**
   * Validate ISO 8601 date string
   */
  public static isValidISO8601(dateStr: string): boolean {
    const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$/;
    return iso8601Regex.test(dateStr) && this.isValidDate(dateStr);
  }

  /**
   * Validate slug (URL-friendly string)
   */
  public static isValidSlug(slug: string): boolean {
    const slugRegex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
    return slugRegex.test(slug);
  }

  /**
   * Validate hex color code
   */
  public static isValidHexColor(color: string): boolean {
    const hexRegex = /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/;
    return hexRegex.test(color);
  }

  /**
   * Sanitize string for SQL (basic - use parameterized queries instead)
   */
  public static sanitizeForSQL(str: string): string {
    return str.replace(/['";\\]/g, '');
  }

  /**
   * Sanitize string for HTML
   */
  public static sanitizeHTML(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Validate against Zod schema
   */
  public static validateWithSchema<T>(schema: z.ZodSchema<T>, data: unknown): {
    success: boolean;
    data?: T;
    errors?: z.ZodError;
  } {
    try {
      const validated = schema.parse(data);
      return { success: true, data: validated };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return { success: false, errors: error };
      }
      return { success: false };
    }
  }

  /**
   * Validate file extension
   */
  public static isValidFileExtension(filename: string, allowedExtensions: string[]): boolean {
    const ext = filename.split('.').pop()?.toLowerCase();
    return ext ? allowedExtensions.includes(ext) : false;
  }

  /**
   * Validate file size
   */
  public static isValidFileSize(sizeInBytes: number, maxSizeInMB: number): boolean {
    const maxSizeInBytes = maxSizeInMB * 1024 * 1024;
    return sizeInBytes <= maxSizeInBytes;
  }

  /**
   * Validate MIME type
   */
  public static isValidMimeType(mimeType: string, allowedTypes: string[]): boolean {
    return allowedTypes.includes(mimeType);
  }

  /**
   * Check if string contains SQL injection patterns
   */
  public static containsSQLInjection(str: string): boolean {
    const sqlInjectionPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/i,
      /(UNION\s+SELECT)/i,
      /(--|\#|\/\*)/,
      /(\bOR\b.*=.*)/i,
      /(\bAND\b.*=.*)/i,
      /(;|\||&)/,
    ];

    return sqlInjectionPatterns.some(pattern => pattern.test(str));
  }

  /**
   * Check if string contains XSS patterns
   */
  public static containsXSS(str: string): boolean {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe/gi,
      /<object/gi,
      /<embed/gi,
    ];

    return xssPatterns.some(pattern => pattern.test(str));
  }

  /**
   * Normalize string
   */
  public static normalize(str: string): string {
    return str.trim().toLowerCase();
  }

  /**
   * Truncate string
   */
  public static truncate(str: string, maxLength: number, suffix: string = '...'): string {
    if (str.length <= maxLength) {
      return str;
    }
    return str.substring(0, maxLength - suffix.length) + suffix;
  }

  /**
   * Check if string is empty or whitespace
   */
  public static isEmpty(str: string): boolean {
    return !str || str.trim().length === 0;
  }
}
