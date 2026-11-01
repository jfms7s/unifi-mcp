#!/usr/bin/env node
import { ConfigError, loadConfig, protectedNetworksLog } from './config.js';
import { createServer } from './mcp/server.js';
import { startHttp, startStdio } from './mcp/transport.js';
import { buildTools } from './tools.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const tools = buildTools(config);

  // stdout carries the MCP protocol on the stdio transport, so log to stderr.
  console.error(
    `unifi-mcp: ${tools.length} tools for ${config.console.baseUrl}${config.readOnly ? ' (read-only)' : ''}`,
  );
  console.error(protectedNetworksLog(config.protectedNetworks));
  if (config.acceptedFindings.length > 0) {
    const pairs = config.acceptedFindings.map((a) => `${a.rule}:${a.object}`);
    console.error(`unifi-mcp: accepted posture findings: ${pairs.join(', ')}`);
  }
  if ('insecure' in config.console.tls) {
    console.error('unifi-mcp: WARNING: TLS verification is off (UNIFI_TLS_INSECURE=true)');
  }

  if (config.transport === 'http' || config.transport === 'both') {
    const http = await startHttp(() => createServer(tools), {
      port: config.port,
      token: config.token as string,
    });
    console.error(`unifi-mcp: http transport listening on port ${config.port}`);

    // PID 1 in a container gets no default signal disposition: without these
    // handlers SIGTERM is ignored and every rollout waits out the grace period.
    for (const signal of ['SIGTERM', 'SIGINT'] as const) {
      process.once(signal, () => {
        const forceExit = setTimeout(() => process.exit(0), 5000);
        forceExit.unref();
        void http.close().then(
          () => process.exit(0),
          (error: unknown) => {
            console.error(error);
            process.exit(1);
          },
        );
      });
    }
  }

  if (config.transport === 'stdio' || config.transport === 'both') {
    await startStdio(createServer(tools));
  }
}

main().catch((error: unknown) => {
  if (error instanceof ConfigError) {
    console.error(`unifi-mcp: ${error.message}`);
    process.exit(2);
  }
  console.error(error);
  process.exit(1);
});
