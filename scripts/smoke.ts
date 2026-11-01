// Live smoke test: calls every read tool once against the configured console.
// Run with the console's env set (see README); never part of CI.
// Prints the tool name, OK/ERR and the output size, never the output itself.
import { loadConfig } from '../src/config.js';
import { UnifiApiError, describeError } from '../src/http/errors.js';
import { buildTools } from '../src/tools.js';

type Args = Record<string, unknown>;

/** The first `id` of a list tool's rows, found without assuming more than the shape. */
function firstId(result: unknown, key: string): string | undefined {
  const rows = (result as Record<string, unknown> | undefined)?.[key];
  const first = Array.isArray(rows) ? (rows[0] as { id?: unknown } | undefined) : undefined;
  return typeof first?.id === 'string' ? first.id : undefined;
}

async function main(): Promise<void> {
  const config = { ...loadConfig(), readOnly: true };
  const tools = buildTools(config);
  const results = new Map<string, unknown>();
  let failures = 0;

  // List tools first: the get tools below need a real id.
  const order = (name: string) => (name.startsWith('unifi_list_') ? 0 : 1);
  const sorted = [...tools].sort((a, b) => order(a.name) - order(b.name));

  for (const tool of sorted) {
    let args: Args = {};
    if (tool.name === 'unifi_get_device')
      args = { device: firstId(results.get('unifi_list_devices'), 'devices') };
    if (tool.name === 'unifi_get_client')
      args = { client: firstId(results.get('unifi_list_clients'), 'clients') };
    if (tool.name === 'unifi_traffic_report') args = { scope: 'site' };

    try {
      const result = await tool.handler(args);
      results.set(tool.name, result);
      const bytes = Buffer.byteLength(JSON.stringify(result) ?? '');
      console.log(`${tool.name.padEnd(28)} OK   ${bytes} bytes`);
    } catch (error) {
      failures++;
      // Kind and status only: a message can quote console content.
      const why =
        error instanceof UnifiApiError
          ? `${error.kind}${error.status ? ` ${error.status}` : ''}`
          : error instanceof Error
            ? error.name
            : 'unknown';
      console.log(`${tool.name.padEnd(28)} ERR  ${why}`);
    }
  }

  console.log(`${tools.length - failures}/${tools.length} OK`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error: unknown) => {
  console.error(describeError(error));
  process.exit(2);
});
