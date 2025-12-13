/**
 * Database Manager
 * 
 * Manages database connections, migrations, and health checks
 */

import { PrismaClient } from '@prisma/client';
import { ConnectionPool } from './pool';

export interface DatabaseConfig {
  url: string;
  poolSize?: number;
  connectionTimeout?: number;
  queryTimeout?: number;
  ssl?: boolean;
  logging?: boolean;
}

export class DatabaseManager {
  private static instance: DatabaseManager;
  private client: PrismaClient | null = null;
  private pool: ConnectionPool | null = null;
  private config: DatabaseConfig;
  private isConnected: boolean = false;

  private constructor(config: DatabaseConfig) {
    this.config = config;
  }

  /**
   * Get singleton instance
   */
  public static getInstance(config?: DatabaseConfig): DatabaseManager {
    if (!DatabaseManager.instance && config) {
      DatabaseManager.instance = new DatabaseManager(config);
    }
    if (!DatabaseManager.instance) {
      throw new Error('DatabaseManager not initialized. Please provide config on first call.');
    }
    return DatabaseManager.instance;
  }

  /**
   * Initialize database connection
   */
  public async connect(): Promise<void> {
    if (this.isConnected) {
      return;
    }

    try {
      this.client = new PrismaClient({
        datasources: {
          db: {
            url: this.config.url,
          },
        },
        log: this.config.logging
          ? ['query', 'info', 'warn', 'error']
          : ['error'],
      });

      // Test connection
      await this.client.$connect();

      // Initialize connection pool if configured
      if (this.config.poolSize) {
        this.pool = new ConnectionPool({
          size: this.config.poolSize,
          databaseUrl: this.config.url,
          timeout: this.config.connectionTimeout,
        });
        await this.pool.initialize();
      }

      this.isConnected = true;
      console.log('Database connected successfully');
    } catch (error) {
      console.error('Failed to connect to database:', error);
      throw error;
    }
  }

  /**
   * Disconnect from database
   */
  public async disconnect(): Promise<void> {
    if (!this.isConnected) {
      return;
    }

    try {
      if (this.pool) {
        await this.pool.close();
      }

      if (this.client) {
        await this.client.$disconnect();
      }

      this.isConnected = false;
      console.log('Database disconnected successfully');
    } catch (error) {
      console.error('Error disconnecting from database:', error);
      throw error;
    }
  }

  /**
   * Get Prisma client
   */
  public getClient(): PrismaClient {
    if (!this.client) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.client;
  }

  /**
   * Get connection pool
   */
  public getPool(): ConnectionPool | null {
    return this.pool;
  }

  /**
   * Health check
   */
  public async healthCheck(): Promise<{
    status: 'healthy' | 'unhealthy';
    message: string;
    details?: any;
  }> {
    try {
      if (!this.client) {
        return {
          status: 'unhealthy',
          message: 'Database client not initialized',
        };
      }

      // Execute a simple query
      const startTime = Date.now();
      await this.client.$queryRaw`SELECT 1`;
      const responseTime = Date.now() - startTime;

      // Check pool status if available
      let poolStatus = null;
      if (this.pool) {
        poolStatus = this.pool.getStatus();
      }

      return {
        status: 'healthy',
        message: 'Database is healthy',
        details: {
          connected: this.isConnected,
          responseTime: `${responseTime}ms`,
          pool: poolStatus,
        },
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Database health check failed',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      };
    }
  }

  /**
   * Execute raw SQL query
   */
  public async executeRaw(query: string, params?: any[]): Promise<any> {
    if (!this.client) {
      throw new Error('Database not connected');
    }

    try {
      return await this.client.$executeRawUnsafe(query, ...( params || []));
    } catch (error) {
      console.error('Error executing raw query:', error);
      throw error;
    }
  }

  /**
   * Execute raw SQL query and return results
   */
  public async queryRaw(query: string, params?: any[]): Promise<any> {
    if (!this.client) {
      throw new Error('Database not connected');
    }

    try {
      return await this.client.$queryRawUnsafe(query, ...(params || []));
    } catch (error) {
      console.error('Error executing raw query:', error);
      throw error;
    }
  }

  /**
   * Begin transaction
   */
  public async transaction<T>(
    fn: (tx: any) => Promise<T>
  ): Promise<T> {
    if (!this.client) {
      throw new Error('Database not connected');
    }

    return await this.client.$transaction(fn);
  }

  /**
   * Get database statistics
   */
  public async getStatistics(): Promise<{
    tables: number;
    totalRecords?: number;
    databaseSize?: string;
  }> {
    try {
      if (!this.client) {
        throw new Error('Database not connected');
      }

      // Get table count (PostgreSQL specific)
      const tables = await this.client.$queryRaw<any[]>`
        SELECT COUNT(*) as count
        FROM information_schema.tables
        WHERE table_schema = 'public'
      `;

      // Get database size (PostgreSQL specific)
      const size = await this.client.$queryRaw<any[]>`
        SELECT pg_size_pretty(pg_database_size(current_database())) as size
      `;

      return {
        tables: parseInt(tables[0]?.count || '0'),
        databaseSize: size[0]?.size,
      };
    } catch (error) {
      console.error('Error getting database statistics:', error);
      return { tables: 0 };
    }
  }

  /**
   * Check if database is connected
   */
  public isHealthy(): boolean {
    return this.isConnected;
  }

  /**
   * Get database configuration
   */
  public getConfig(): DatabaseConfig {
    return { ...this.config };
  }

  /**
   * Update database configuration
   */
  public async updateConfig(config: Partial<DatabaseConfig>): Promise<void> {
    this.config = { ...this.config, ...config };

    // Reconnect with new configuration
    if (this.isConnected) {
      await this.disconnect();
      await this.connect();
    }
  }

  /**
   * Run migrations (placeholder - implement based on your migration strategy)
   */
  public async runMigrations(): Promise<void> {
    console.log('Running migrations...');
    // Implement migration logic here
    // This could use Prisma migrate or custom migration logic
  }

  /**
   * Seed database (placeholder - implement based on your seeding strategy)
   */
  public async seed(): Promise<void> {
    console.log('Seeding database...');
    // Implement seeding logic here
  }
}
