/**
 * CSRF Token Generation Handler
 * 
 * Provides endpoint for generating CSRF tokens for authenticated users
 */

import { createAuthenticatedHandler } from './handler';
import { CSRFProtection } from '../security/csrf';

/**
 * Generate CSRF token for authenticated user
 * 
 * @example
 * GET /api/csrf-token
 * Authorization: Bearer <jwt-token>
 * 
 * Response:
 * {
 *   "success": true,
 *   "data": {
 *     "csrfToken": "abc123...",
 *     "expiresIn": 3600
 *   }
 * }
 */
export const generateCSRFToken = createAuthenticatedHandler({
    handler: async ({ user }) => {
        const csrfProtection = CSRFProtection.getInstance();
        const token = await csrfProtection.generateToken(user!.id);

        return {
            csrfToken: token,
            expiresIn: 3600, // 1 hour
            headerName: 'X-CSRF-Token',
        };
    },
    auditConfig: {
        enabled: true,
        action: 'csrf.token.generated',
        category: 'SECURITY' as any,
    },
});

/**
 * Refresh CSRF token (extend TTL)
 * 
 * @example
 * POST /api/csrf-token/refresh
 * Authorization: Bearer <jwt-token>
 * X-CSRF-Token: <current-token>
 * 
 * Response:
 * {
 *   "success": true,
 *   "data": {
 *     "refreshed": true,
 *     "expiresIn": 3600
 *   }
 * }
 */
export const refreshCSRFToken = createAuthenticatedHandler({
    handler: async ({ request }) => {
        const csrfProtection = CSRFProtection.getInstance();
        const currentToken = request.get('X-CSRF-Token');

        if (!currentToken) {
            throw new Error('CSRF token required for refresh');
        }

        const refreshed = await csrfProtection.refreshToken(currentToken);

        if (!refreshed) {
            throw new Error('Invalid or expired CSRF token');
        }

        return {
            refreshed: true,
            expiresIn: 3600,
        };
    },
    auditConfig: {
        enabled: true,
        action: 'csrf.token.refreshed',
        category: 'SECURITY' as any,
    },
});
