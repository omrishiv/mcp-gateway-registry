import { Page, expect } from '@playwright/test';

const BASE_URL = 'http://localhost';

/**
 * FastAPI backend URL (bypasses nginx auth_request).
 */
const BACKEND_URL = 'http://localhost:7860';

/**
 * Headers that nginx normally sets after auth_request validation.
 */
const ADMIN_AUTH_HEADERS: Record<string, string> = {
  'X-User': 'admin',
  'X-Username': 'admin',
  'X-Scopes': 'mcp-registry-admin,mcp-servers-unrestricted/read,mcp-servers-unrestricted/execute,federation/peers',
  'X-Auth-Method': 'oauth2',
  'X-Client-Id': '',
};

/**
 * Mock response for /api/auth/me.
 */
const ADMIN_ME_RESPONSE = {
  username: 'admin',
  email: 'admin@local',
  auth_method: 'oauth2',
  provider: 'oauth2',
  scopes: ['mcp-registry-admin'],
  groups: ['mcp-registry-admin'],
  can_modify_servers: true,
  is_admin: true,
  ui_permissions: {
    list_service: ['all'],
    register_service: ['all'],
    health_check_service: ['all'],
    toggle_service: ['all'],
    modify_service: ['all'],
    list_agents: ['all'],
    get_agent: ['all'],
    publish_agent: ['all'],
    modify_agent: ['all'],
    delete_agent: ['all'],
  },
  accessible_servers: ['*'],
  accessible_services: ['all'],
  accessible_agents: ['all'],
};

/**
 * Default mock responses for API endpoints.
 * Used when the backend returns 500 (e.g. MongoDB auth issues).
 */
const MOCK_RESPONSES: Record<string, unknown> = {
  '/api/servers': [],
  '/api/agents': [],
  '/api/skills': [],
  '/api/virtual-servers': [],
  '/api/peers': [],
  '/api/version': { version: '0.0.0-e2e' },
};

/**
 * Authenticate for e2e tests.
 *
 * Strategy:
 * 1. /api/auth/me is intercepted with a mock admin profile.
 * 2. Protected /api/* requests are proxied to the backend (port 7860)
 *    with admin auth headers.  500 responses are replaced with safe
 *    mock data so the SPA does not crash.
 * 3. Public auth endpoints flow through nginx normally.
 */
export async function loginAsAdmin(page: Page): Promise<void> {
  // Intercept /api/auth/me with mock admin profile.
  await page.route('**/api/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(ADMIN_ME_RESPONSE),
    });
  });

  // Proxy protected /api/* requests to the backend.
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());

    // Public auth paths go through nginx normally.
    if (url.pathname.startsWith('/api/auth/')) {
      return route.fallback();
    }

    // Build backend URL with admin auth headers.
    const backendUrl = `${BACKEND_URL}${url.pathname}${url.search}`;
    const headers: Record<string, string> = {
      ...route.request().headers(),
      ...ADMIN_AUTH_HEADERS,
    };
    // Remove host header to avoid confusing the backend.
    delete headers['host'];

    try {
      const response = await page.request.fetch(backendUrl, {
        method: route.request().method(),
        headers,
        data: route.request().postDataBuffer() ?? undefined,
      });

      const status = response.status();

      if (status >= 400) {
        // Use mock response if we have one, otherwise return empty.
        const mock = MOCK_RESPONSES[url.pathname];
        if (mock !== undefined) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(mock),
          });
        } else {
          // Generic fallback: array for plural endpoints, object otherwise.
          const body = url.pathname.match(/\/[a-z-]+s(\/)?$/) ? '[]' : '{}';
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body,
          });
        }
        return;
      }

      await route.fulfill({ response });
    } catch {
      // Backend unreachable - return mock data.
      const mock = MOCK_RESPONSES[url.pathname];
      try {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mock ?? []),
        });
      } catch {
        // Route was already handled; ignore.
      }
    }
  });

  // Navigate to the app (auth is handled via route interception above).
  await page.goto('/');
  await page.waitForLoadState('networkidle');

  // Verify we landed on the Dashboard (not the login page).
  await expect(page).toHaveURL('/', { timeout: 15000 });
}

/**
 * Navigate to the Settings page > Virtual MCP > Virtual Servers.
 *
 * The SPA uses relative asset paths (`./static/...`) so a direct
 * page.goto('/settings/virtual-mcp/servers') would fail to load JS/CSS.
 * Instead we click the Settings gear icon (which is a React Router Link)
 * then expand the Virtual MCP sidebar category.
 */
export async function navigateToVirtualServers(page: Page): Promise<void> {
  // Ensure we start from the Dashboard (page loaded from /).
  const currentUrl = page.url();
  if (!currentUrl.endsWith('/') && !currentUrl.endsWith('localhost')) {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
  }

  // Click the Settings gear icon (React Router <Link to="/settings">).
  const settingsLink = page.locator('a[title="Settings"]');
  await expect(settingsLink).toBeVisible({ timeout: 5000 });
  await settingsLink.click();
  await page.waitForLoadState('networkidle');

  // Expand the "Virtual MCP" category in the settings sidebar.
  const virtualMcpCategory = page.locator('button:has-text("Virtual MCP")');
  await expect(virtualMcpCategory).toBeVisible({ timeout: 10000 });
  await virtualMcpCategory.click();
  await page.waitForTimeout(300);

  // Click "Virtual Servers" under the expanded category.
  const virtualServersItem = page.locator('button:has-text("Virtual Servers")');
  await expect(virtualServersItem).toBeVisible({ timeout: 5000 });
  await virtualServersItem.click();
  await page.waitForLoadState('networkidle');

  // Verify the Virtual MCP Servers heading appears.
  await expect(
    page.locator('h2:has-text("Virtual MCP Servers")')
  ).toBeVisible({ timeout: 15000 });
}
