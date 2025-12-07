# Secure API Handler Template

A comprehensive, enterprise-grade API handler framework for **Node.js + Express + Prisma** to build secure, multi-tenant systems with authentication, sanitization, encryption, rate limiting, caching, and observability.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.2-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.18-lightgrey.svg)](https://expressjs.com/)
[![Prisma](https://img.shields.io/badge/Prisma-5.6-green.svg)](https://prisma.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🚀 Features

### Core Security
- **Authentication** - JWT, API Key, OAuth strategies
- **Input Sanitization** - HTML, SQL injection, XSS protection
- **Data Encryption** - AES-256-GCM encryption with key management
- **Rate Limiting** - Redis-based distributed rate limiting
- **Request Validation** - Zod schema validation

### Multi-Tenant Support
- **Tenant Isolation** - Shared schema, separate schema, separate database
- **Tenant Context** - Automatic tenant resolution and context management
- **Resource Ownership** - Automatic ownership verification

### Performance & Reliability
- **Caching Layer** - Redis + Memory cache with invalidation
- **API Versioning** - URL-based and header-based versioning
- **Health Checks** - Comprehensive system health monitoring
- **Monitoring & Observability** - Metrics, tracing, error tracking

### Developer Experience
- **TypeScript** - Full type safety and IntelliSense
- **Feature Flags** - Dynamic feature toggles
- **Configuration Management** - Environment-based config
- **Comprehensive Documentation** - API reference and guides

## 📦 Installation

```bash
# Clone the template
git clone https://github.com/RkayG/secure-api-request-handler
cd secure-api-request-handler

# Install dependencies
npm install

# Set up Prisma
npx prisma generate

# Copy environment file
cp .env.example .env

# Configure your environment variables
nano .env

# Run database migrations
npx prisma db push

# Start the development server
npm run dev
```

## ⚡ Quick Start

### 1. Basic API Handler

```typescript
import express from 'express';
import { createHandler } from 'secure-api-handler';

const app = express();

// Basic GET handler
app.get('/api/items', createHandler({
  schema: z.object({
    limit: z.number().min(1).max(100).optional().default(10),
    offset: z.number().min(0).optional().default(0),
  }),
  handler: async ({ input, prisma }) => {
    const { limit, offset } = input;

    const items = await prisma.item.findMany({
      skip: offset,
      take: limit,
      orderBy: { createdAt: 'desc' },
    });

    return items;
  },
}));

app.listen(3000, () => console.log('Server running on port 3000'));
```

### 2. Authenticated Handler with Ownership

```typescript
import { Router } from 'express';
import { createAuthenticatedHandler } from 'secure-api-handler';

const router = Router();

// PUT /api/projects/:id
router.put('/projects/:id', createAuthenticatedHandler({
  schema: z.object({
    name: z.string().min(1).max(200),
    description: z.string().max(1000).optional(),
  }),
  requireOwnership: {
    model: 'Project',
    resourceIdParam: 'id',
    ownerIdField: 'ownerId',
    selectFields: ['id', 'name', 'ownerId'],
  },
  handler: async ({ input, prisma, params, resource }) => {
    const project = await prisma.project.update({
      where: { id: params.id },
      data: input,
      select: { id: true, name: true, description: true, updatedAt: true },
    });
    return project;
  },
}));

export default router;
```

### 3. Advanced Handler with Caching & Rate Limiting

```typescript
import { Router } from 'express';
import { createHandler } from 'secure-api-handler';

const router = Router();

// GET /api/products
router.get('/products', createHandler({
  schema: z.object({
    category: z.string().optional(),
    limit: z.number().min(1).max(100).default(20),
    offset: z.number().min(0).default(0),
  }),
  cache: {
    ttl: 300, // 5 minutes
    keyGenerator: (req) => `products:${req.query.category || 'all'}:${req.query.limit}:${req.query.offset}`,
  },
  rateLimit: {
    windowMs: 60000, // 1 minute
    maxRequests: 100,
  },
  handler: async ({ input, prisma }) => {
    const { category, limit, offset } = input;

    const whereClause: any = {};
    if (category) {
      whereClause.category = category;
    }

    const [products, total] = await Promise.all([
      prisma.product.findMany({
        where: whereClause,
        skip: offset,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.product.count({ where: whereClause }),
    ]);

    return {
      products,
      pagination: {
        limit,
        offset,
        total,
        hasMore: offset + limit < total,
      },
    };
  },
}));

export default router;
```

## 🏗️ Architecture

```
secure-api-handler/
├── core/                    # Core framework (Express middleware)
│   ├── handler.ts          # Main API handler factory
│   ├── types.ts            # TypeScript definitions
│   └── response.ts         # Response utilities
├── prisma/                 # Database schema & migrations
│   └── schema.prisma       # Prisma schema definition
├── auth/                    # Authentication strategies
│   ├── strategies/         # JWT, API Key, OAuth
│   └── manager.ts          # Auth manager
├── security/                # Security features
│   ├── sanitization.ts     # Input/output sanitization
│   ├── encryption.ts       # Data encryption
│   └── rate-limiting.ts    # Rate limiting
├── caching/                 # Caching layer
│   ├── redis.ts            # Redis cache
│   ├── memory.ts           # Memory cache
│   └── manager.ts          # Cache manager
├── monitoring/              # Observability
│   ├── service.ts          # Monitoring service
│   └── health.ts           # Health checks
├── versioning/              # API versioning
│   ├── manager.ts          # Version manager
│   └── strategies/         # URL/Header strategies
├── config/                  # Configuration
│   ├── manager.ts          # Config manager
│   └── feature-flags.ts    # Feature flags
├── multitenancy/            # Multi-tenant support
├── database/                # Database utilities
└── utils/                   # Helper utilities
```

## 🔧 Configuration

### Environment Variables

```bash
# Database (Prisma)
DATABASE_URL=postgresql://user:password@localhost:5432/secure_api
# For MySQL: mysql://user:password@localhost:3306/secure_api

# Authentication
JWT_SECRET=your-super-secret-jwt-key
AUTH_STRATEGIES=jwt,api_key

# Security
ENCRYPTION_KEY=your-encryption-key
RATE_LIMITING_ENABLED=true
XSS_PROTECTION_ENABLED=true

# Caching
CACHE_PROVIDER=redis
REDIS_URL=redis://localhost:6379
CACHE_DEFAULT_TTL=300

# Monitoring
MONITORING_PROVIDER=datadog
SERVICE_NAME=my-api
MONITORING_API_KEY=your-api-key

# Multi-tenancy
MULTITENANCY_ENABLED=true
MULTITENANCY_STRATEGY=shared_schema
TENANT_HEADER=X-Tenant-ID

# Feature Flags
FEATURE_ADVANCED_ANALYTICS=true
FEATURE_EXPERIMENTAL_UI=false
```

### Feature Flags

Enable or disable features dynamically:

```typescript
import { FeatureFlags } from 'secure-api-handler';

const features = FeatureFlags.getInstance();

// Enable a feature
features.enable('advanced-analytics');

// Check if feature is enabled
if (features.isEnabled('advanced-analytics', { userId: '123' })) {
  // Show advanced analytics
}

// Override for specific user
features.overrideForUser('experimental-ui', 'user-123', true);
```

## 🔒 Security Features

### Input Sanitization

Automatic sanitization of all inputs:

```typescript
// HTML sanitization
const cleanHtml = sanitizeService.sanitizeHTML('<script>alert("xss")</script>');
// Result: <p>alert("xss")</p>

// SQL injection prevention
const safeQuery = sanitizeService.preventSQLInjection("'; DROP TABLE users; --");
// Result: anitized input

// Sensitive data masking
const masked = sanitizeService.maskSensitiveData("password: secret123");
// Result: password: *********
```

### Data Encryption

Encrypt sensitive data automatically:

```typescript
import { EncryptionService } from 'secure-api-handler';

const encryption = EncryptionService.getInstance();

// Encrypt data
const encrypted = await encryption.encrypt({ password: 'secret' });

// Decrypt data
const decrypted = await encryption.decrypt(encrypted);
```

### Rate Limiting

Distributed rate limiting with Redis:

```typescript
rateLimit: {
  windowMs: 60000,    // 1 minute
  maxRequests: 100,   // 100 requests per minute
  keyGenerator: (req, user) => `api:${user?.id}:${req.nextUrl.pathname}`,
}
```

### Dependency Scanning

Automated security scanning for vulnerable dependencies:

#### npm audit (Built-in)

The project includes npm audit scripts for security scanning:

```bash
# Check for vulnerabilities
npm run audit

# Fix automatically fixable issues
npm run audit:fix

# Check only production dependencies
npm run audit:production

# Get JSON output for CI/CD
npm run audit:json

# Check with custom severity level
npm run security:check
```

#### Dependabot (GitHub)

Automated dependency updates via Dependabot are configured in `.github/dependabot.yml`:

- **Weekly updates** - Checks for updates every Monday
- **Security-first** - Prioritizes security vulnerabilities
- **Grouped PRs** - Groups updates to reduce PR noise
- **Auto-labeling** - Labels PRs with `dependencies` and `security`

Dependabot will automatically:
- Create PRs for security vulnerabilities
- Update dependencies weekly
- Group related updates together
- Ignore major version updates (for manual review)

#### Alternative: Snyk

For more advanced scanning, you can use Snyk:

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities
snyk test

# Monitor project
snyk monitor

# Fix vulnerabilities
snyk wizard
```

**Recommendation**: Use **npm audit** for quick checks and **Dependabot** for automated updates. Snyk is optional for teams needing advanced features like license compliance and container scanning.

## 📊 Monitoring & Observability

### Health Checks

```typescript
import { HealthChecker } from 'secure-api-handler';

const healthChecker = HealthChecker.getInstance();

// Add database health check
healthChecker.registerCheck(
  'database',
  HealthChecker.createDatabaseCheck('database', async () => {
    const client = getDatabaseClient();
    await client.query('SELECT 1');
    return true;
  })
);

// Add Redis health check
healthChecker.registerCheck(
  'redis',
  HealthChecker.createRedisCheck('redis', redisClient)
);

// Check overall health
const health = await healthChecker.getOverallHealth();
console.log(health.status); // 'healthy' | 'unhealthy' | 'degraded'
```

### Metrics & Tracing

```typescript
import { MonitoringService } from 'secure-api-handler';

const monitoring = MonitoringService.getInstance();

// Record custom metrics
monitoring.recordMetric('api.requests', 1, {
  method: 'GET',
  endpoint: '/api/users',
  status: 200,
});

// Start a trace span
const spanId = monitoring.startSpan('user-creation', {
  userId: '123',
  email: 'user@example.com',
});

// End the span
monitoring.endSpan(spanId, 'ok');
```

## 🏢 Multi-Tenant Support

### Configuration

```typescript
multitenancy: {
  enabled: true,
  strategy: 'shared_schema', // 'shared_schema' | 'separate_schema' | 'separate_database'
  tenantHeader: 'X-Tenant-ID',
}
```

### Tenant-Aware Handlers

```typescript
export const GET = createTenantHandler({
  handler: async ({ tenant, supabase }) => {
    // Tenant context is automatically available
    const { data } = await supabase
      .from('users')
      .select('*')
      .eq('tenant_id', tenant.id);

    return data;
  },
});
```

## 🏷️ API Versioning

### URL-Based Versioning

```
GET /api/v1/users
GET /api/v2/users
```

### Header-Based Versioning

```typescript
// Accept-Version: v2
GET /api/users
```

### Version Management

```typescript
import { VersionManager } from 'secure-api-handler';

const versionManager = VersionManager.getInstance();

// Check version compatibility
const isCompatible = versionManager.isVersionSupported('v1', 'v1');

// Deprecate a version
versionManager.deprecateVersion('v1', new Date('2024-12-31'));
```

## 🐳 Docker & Deployment

### Docker Setup

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
COPY prisma/ ./prisma/
RUN npm ci --only=production

# Generate Prisma client
RUN npx prisma generate

COPY dist/ ./dist/
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["npm", "start"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://user:password@db:5432/app
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=app
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password

  redis:
    image: redis:7-alpine
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run integration tests
npm run test:integration

# Run e2e tests
npm run test:e2e
```

## 📚 Examples

Check out the `examples/` directory for complete implementations:

- `examples/basic-api/` - Simple CRUD API
- `examples/multi-tenant-app/` - Multi-tenant application
- `examples/advanced-features/` - Advanced features showcase

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Zod](https://zod.dev/) - TypeScript-first schema validation
- [Redis](https://redis.io/) - In-memory data structure store
- [DOMPurify](https://github.com/cure53/DOMPurify) - XSS sanitizer
