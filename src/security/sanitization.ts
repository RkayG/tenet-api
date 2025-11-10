/**
 * Data Sanitization Service
 *
 * Provides comprehensive sanitization for:
 * - HTML content
 * - SQL injection prevention
 * - XSS protection
 * - Sensitive data masking
 */

import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import {
  SanitizationConfig,
  HtmlSanitizationConfig,
  SqlSanitizationConfig,
  XssProtectionConfig,
  SensitiveDataConfig,
} from '../core/types';

// Initialize DOMPurify with JSDOM for server-side usage
const window = new JSDOM('').window;
const DOMPurifyServer = DOMPurify(window as any);

// SQL injection patterns to detect and prevent
const SQL_INJECTION_PATTERNS = [
  /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/gi,
  /(-{2}|\/\*|\*\/)/g, // Comments
  /('|(\\x27)|(\\x2D))/g, // Quotes and dashes
  /(;|(\\x3B))/g, // Semicolons
  /(<script|javascript:|vbscript:|onload|onerror)/gi, // Script injections
];

// XSS patterns to detect
const XSS_PATTERNS = [
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /onload\s*=/gi,
  /onerror\s*=/gi,
  /onclick\s*=/gi,
  /onmouseover\s*=/gi,
  /<iframe[^>]*>/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  /<form[^>]*>/gi,
  /<input[^>]*>/gi,
  /<meta[^>]*>/gi,
  /<link[^>]*>/gi,
];

// Sensitive data patterns for masking
const SENSITIVE_PATTERNS = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  phone: /(\+?1?[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
  credit_card: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
  api_key: /\b[A-Za-z0-9]{32,}\b/g, // Generic API key pattern
  password: /password["\s]*:[\s]*["']([^"']+)["']/gi,
  token: /token["\s]*:[\s]*["']([^"']+)["']/gi,
};

export class SanitizationService {
  private static instance: SanitizationService;
  private config: SanitizationConfig;

  private constructor(config: SanitizationConfig = {}) {
    this.config = {
      html: {
        allowedTags: ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'a'],
        allowedAttributes: {
          a: ['href', 'title'],
        },
        ...config.html,
      },
      sql: {
        allowedOperators: ['=', '!=', '<', '>', '<=', '>=', 'LIKE', 'IN'],
        maxQueryLength: 10000,
        preventInjection: true,
        ...config.sql,
      },
      xss: {
        enabled: true,
        escapeHtml: true,
        ...config.xss,
      },
      sensitive: {
        fields: ['password', 'token', 'api_key', 'secret', 'private_key'],
        maskCharacter: '*',
        maskLength: 8,
        ...config.sensitive,
      },
      ...config,
    };
  }

  public static getInstance(config?: SanitizationConfig): SanitizationService {
    if (!SanitizationService.instance) {
      SanitizationService.instance = new SanitizationService(config);
    }
    return SanitizationService.instance;
  }

  /**
   * Sanitize input data comprehensively
   */
  public async sanitize(input: any): Promise<any> {
    if (typeof input !== 'object' || input === null) {
      return this.sanitizeValue(input);
    }

    const sanitized: any = Array.isArray(input) ? [] : {};

    for (const [key, value] of Object.entries(input)) {
      const sanitizedKey = this.sanitizeString(key);
      const sanitizedValue = await this.sanitize(value);
      sanitized[sanitizedKey] = sanitizedValue;
    }

    return sanitized;
  }

  /**
   * Sanitize a single value
   */
  private sanitizeValue(value: any): any {
    if (typeof value === 'string') {
      return this.sanitizeString(value);
    }

    if (typeof value === 'object' && value !== null) {
      return this.sanitize(value);
    }

    return value;
  }

  /**
   * Sanitize a string value with all protections
   */
  public sanitizeString(value: string): string {
    if (typeof value !== 'string') {
      return value;
    }

    let sanitized = value;

    // Apply XSS protection
    if (this.config.xss?.enabled) {
      sanitized = this.preventXSS(sanitized);
    }

    // Apply SQL injection prevention
    if (this.config.sql?.preventInjection) {
      sanitized = this.preventSQLInjection(sanitized);
    }

    // Apply HTML sanitization
    sanitized = this.sanitizeHTML(sanitized);

    return sanitized;
  }

  /**
   * Sanitize HTML content
   */
  public sanitizeHTML(html: string): string {
    if (!this.config.html) {
      return html;
    }

    try {
      return DOMPurifyServer.sanitize(html, {
        ALLOWED_TAGS: this.config.html.allowedTags,
        ALLOWED_ATTR: this.config.html.allowedAttributes,
        ALLOW_DATA_ATTR: false,
        ALLOW_UNKNOWN_PROTOCOLS: false,
        SANITIZE_DOM: true,
        KEEP_CONTENT: true,
      });
    } catch (error) {
      console.warn('HTML sanitization failed, returning escaped content:', error);
      return this.escapeHtml(html);
    }
  }

  /**
   * Prevent SQL injection attacks
   */
  public preventSQLInjection(input: string): string {
    if (!this.config.sql?.preventInjection) {
      return input;
    }

    let sanitized = input;

    // Remove or escape dangerous SQL patterns
    for (const pattern of SQL_INJECTION_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Limit query length
    if (this.config.sql.maxQueryLength && sanitized.length > this.config.sql.maxQueryLength) {
      sanitized = sanitized.substring(0, this.config.sql.maxQueryLength);
    }

    return sanitized;
  }

  /**
   * Prevent XSS attacks
   */
  public preventXSS(input: string): string {
    if (!this.config.xss?.enabled) {
      return input;
    }

    let sanitized = input;

    // Remove dangerous patterns
    for (const pattern of XSS_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Apply custom patterns
    if (this.config.xss.customPatterns) {
      for (const pattern of this.config.xss.customPatterns) {
        sanitized = sanitized.replace(pattern, '');
      }
    }

    // Escape HTML if configured
    if (this.config.xss.escapeHtml) {
      sanitized = this.escapeHtml(sanitized);
    }

    return sanitized;
  }

  /**
   * Escape HTML characters
   */
  private escapeHtml(text: string): string {
    const htmlEscapes: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
    };

    return text.replace(/[&<>"'/]/g, (match) => htmlEscapes[match]);
  }

  /**
   * Sanitize response data (mask sensitive information)
   */
  public async sanitizeResponse(data: any): Promise<any> {
    if (typeof data !== 'object' || data === null) {
      return data;
    }

    const sanitized: any = Array.isArray(data) ? [] : {};

    for (const [key, value] of Object.entries(data)) {
      // Check if this field should be masked
      if (this.config.sensitive?.fields.includes(key.toLowerCase())) {
        sanitized[key] = this.maskSensitiveData(String(value));
      } else {
        sanitized[key] = await this.sanitizeResponse(value);
      }
    }

    return sanitized;
  }

  /**
   * Mask sensitive data in strings
   */
  public maskSensitiveData(value: string): string {
    if (!this.config.sensitive) {
      return value;
    }

    const { maskCharacter = '*', maskLength = 8 } = this.config.sensitive;

    // Apply pattern-based masking
    let masked = value;

    for (const [type, pattern] of Object.entries(SENSITIVE_PATTERNS)) {
      if (this.config.sensitive.fields.includes(type)) {
        masked = masked.replace(pattern, (match) => {
          if (match.length <= 4) return maskCharacter.repeat(match.length);
          return match.substring(0, 2) + maskCharacter.repeat(maskLength) + match.substring(match.length - 2);
        });
      }
    }

    // Mask entire field if it's in sensitive fields list
    return masked;
  }

  /**
   * Validate if input is safe
   */
  public validateSafety(input: any): { isSafe: boolean; violations: string[] } {
    const violations: string[] = [];

    const checkValue = (value: any, path: string = ''): void => {
      if (typeof value === 'string') {
        // Check for SQL injection
        for (const pattern of SQL_INJECTION_PATTERNS) {
          if (pattern.test(value)) {
            violations.push(`SQL injection pattern detected at ${path}`);
          }
        }

        // Check for XSS
        for (const pattern of XSS_PATTERNS) {
          if (pattern.test(value)) {
            violations.push(`XSS pattern detected at ${path}`);
          }
        }
      } else if (typeof value === 'object' && value !== null) {
        for (const [key, val] of Object.entries(value)) {
          checkValue(val, path ? `${path}.${key}` : key);
        }
      }
    };

    checkValue(input);

    return {
      isSafe: violations.length === 0,
      violations,
    };
  }

  /**
   * Update sanitization configuration
   */
  public updateConfig(config: Partial<SanitizationConfig>): void {
    this.config = {
      ...this.config,
      ...config,
      html: { ...this.config.html, ...config.html },
      sql: { ...this.config.sql, ...config.sql },
      xss: { ...this.config.xss, ...config.xss },
      sensitive: { ...this.config.sensitive, ...config.sensitive },
    };
  }

  /**
   * Get current configuration
   */
  public getConfig(): SanitizationConfig {
    return { ...this.config };
  }
}
