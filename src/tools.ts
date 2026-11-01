import type { UnifiMcpConfig } from './config.js';
import { createUnifiHttpClient } from './http/client.js';
import type { ToolDefinition } from './mcp/types.js';
import { loadProtectedScope } from './unifi/guard.js';
import { createLegacyApi } from './unifi/legacy.js';
import { createOfficialApi } from './unifi/official.js';
import { createReadTools } from './unifi/read-tools.js';
import { createSiteManagerApi } from './unifi/sitemanager.js';
import { createSiteResolver } from './unifi/sites.js';
import { createSyslogApi } from './unifi/syslog.js';
import { consoleHost } from './unifi/write-tools/common.js';
import { createWriteTools, lazyScope } from './unifi/write-tools/index.js';

/** Read tools, plus the change tools unless read-only; Site Manager tools only with its key. */
export function buildTools(config: UnifiMcpConfig): ToolDefinition[] {
  const client = createUnifiHttpClient(config);
  const deps = {
    official: createOfficialApi(client),
    legacy: createLegacyApi(client),
    syslog: createSyslogApi(client),
    sitemanager: config.siteManagerApiKey ? createSiteManagerApi(client) : undefined,
    sites: createSiteResolver(client),
  };

  const tools = createReadTools(deps);
  if (config.readOnly) return tools;
  const scope = lazyScope(async () =>
    loadProtectedScope(config.protectedNetworks, deps, await deps.sites.resolve()),
  );
  return [
    ...tools,
    ...createWriteTools({ ...deps, scope, consoleHost: consoleHost(config.console.baseUrl) }),
  ];
}
