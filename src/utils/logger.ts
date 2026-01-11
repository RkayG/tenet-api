/**
 * Logger Utility
 * 
 * Provides structured logging with different levels and formats
 */

import * as winston from 'winston';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LoggerConfig {
  level?: LogLevel;
  format?: 'json' | 'text';
  enableConsole?: boolean;
  enableFile?: boolean;
  filePath?: string;
  maxSize?: string;
  maxFiles?: number;
}

export class Logger {
  private static instance: Logger;
  private logger: winston.Logger;
  private config: LoggerConfig;

  private constructor(config: LoggerConfig = {}) {
    this.config = {
      level: config.level || 'info',
      format: config.format || 'json',
      enableConsole: config.enableConsole !== false,
      enableFile: config.enableFile || false,
      filePath: config.filePath || 'logs/app.log',
      maxSize: config.maxSize || '10m',
      maxFiles: config.maxFiles || 5,
    };

    this.logger = this.createLogger();
  }

  /**
   * Get singleton instance
   */
  public static getInstance(config?: LoggerConfig): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger(config);
    }
    return Logger.instance;
  }

  /**
   * Create Winston logger instance
   */
  private createLogger(): winston.Logger {
    const transports: winston.transport[] = [];

    // Console transport
    if (this.config.enableConsole) {
      transports.push(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.timestamp(),
            this.config.format === 'json'
              ? winston.format.json()
              : winston.format.simple()
          ),
        })
      );
    }

    // File transport
    if (this.config.enableFile) {
      transports.push(
        new winston.transports.File({
          filename: this.config.filePath!,
          maxsize: this.parseSize(this.config.maxSize!),
          maxFiles: this.config.maxFiles!,
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
          ),
        })
      );
    }

    return winston.createLogger({
      level: this.config.level!,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      transports,
    });
  }

  /**
   * Parse size string to bytes
   */
  private parseSize(size: string): number {
    const units: Record<string, number> = {
      b: 1,
      k: 1024,
      m: 1024 * 1024,
      g: 1024 * 1024 * 1024,
    };

    const match = size.match(/^(\d+)([bkmg]?)$/i);
    if (!match) {
      return 10 * 1024 * 1024; // Default 10MB
    }

    const value = parseInt(match[1]!);
    const unit = (match[2] || 'b').toLowerCase();

    return value * (units[unit] || 1);
  }

  /**
   * Log debug message
   */
  public debug(message: string, meta?: Record<string, any>): void {
    this.logger.debug(message, meta);
  }

  /**
   * Log info message
   */
  public info(message: string, meta?: Record<string, any>): void {
    this.logger.info(message, meta);
  }

  /**
   * Log warning message
   */
  public warn(message: string, meta?: Record<string, any>): void {
    this.logger.warn(message, meta);
  }

  /**
   * Log error message
   */
  public error(message: string, error?: Error | any, meta?: Record<string, any>): void {
    const errorMeta = error instanceof Error
      ? {
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name,
        },
        ...meta,
      }
      : { error, ...meta };

    this.logger.error(message, errorMeta);
  }

  /**
   * Log with custom level
   */
  public log(level: LogLevel, message: string, meta?: Record<string, any>): void {
    this.logger.log(level, message, meta);
  }

  /**
   * Create child logger with default metadata
   */
  public child(defaultMeta: Record<string, any>): winston.Logger {
    return this.logger.child(defaultMeta);
  }

  /**
   * Set log level
   */
  public setLevel(level: LogLevel): void {
    this.logger.level = level;
    this.config.level = level;
  }

  /**
   * Get current log level
   */
  public getLevel(): LogLevel {
    return this.config.level!;
  }

  /**
   * Log HTTP request
   */
  public logRequest(data: any): void {
    const { method, path, url, ip, userId, statusCode, duration } = data;
    this.info(`HTTP Request: ${method} ${path || url}`, {
      method,
      url: path || url,
      ip,
      userId,
      statusCode,
      duration,
    });
  }

  /**
   * Log HTTP response
   */
  public logResponse(req: any, res: any, duration: number): void {
    this.info('HTTP Response', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      requestId: req.id,
    });
  }

  /**
   * Log database query
   */
  public logQuery(query: string, duration: number, metadata: Record<string, any> = {}): void {
    const logData = {
      query,
      duration,
      ...metadata,
    };

    if (duration >= 1000) {
      this.warn('Slow Database Query', logData);
    } else {
      this.debug('Database Query', logData);
    }
  }

  /**
   * Log authentication event
   */
  public logAuth(event: string, details: Record<string, any> = {}): void {
    if (event.toLowerCase().includes('success')) {
      this.info(`Authentication Success: ${event}`, details);
    } else {
      this.warn(`Authentication Failure: ${event}`, details);
    }
  }

  /**
   * Log security event
   */
  public logSecurity(event: string, metadata: any = {}): void {
    let severity = 'medium';
    if (typeof metadata === 'string') {
      severity = metadata;
      metadata = {};
    } else if (metadata.severity) {
      severity = metadata.severity;
    }

    const level = severity === 'critical' || severity === 'high' ? 'error' : 'warn';
    const message = `Security Event: ${event}`;

    if (level === 'error') {
      this.error(message, undefined, metadata);
    } else {
      this.warn(message, metadata);
    }
  }

  /**
   * Alias for logRequest
   */
  public request(req: any): void {
    this.logRequest(req);
  }

  /**
   * Alias for logSecurity
   */
  public security(event: string, metadata: any = {}): void {
    this.logSecurity(event, metadata);
  }

  /**
   * Alias for logAuth
   */
  public auth(event: string, details: any = {}): void {
    this.logAuth(event, details);
  }

  /**
   * Alias for logQuery
   */
  public query(query: string, duration: any, params?: any): void {
    if (typeof duration === 'object' && duration.duration !== undefined) {
      this.logQuery(query, duration.duration, duration);
    } else {
      this.logQuery(query, duration, params);
    }
  }

  /**
   * Get logger configuration
   */
  public getConfig(): LoggerConfig {
    return { ...this.config };
  }
}

// Export default instance
export const logger = Logger.getInstance();
