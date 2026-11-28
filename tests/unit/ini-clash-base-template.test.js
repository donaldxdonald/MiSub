import { afterEach, describe, expect, it, vi } from 'vitest';
import yaml from 'js-yaml';
import { ProcessorService } from '../../functions/services/processor-service.js';

const TEMPLATE_URL = 'https://example.com/full.ini';
const BASE_URL = 'https://example.com/base.yaml';
const TEMPLATE = `
[custom]
clash_rule_base=${BASE_URL}
custom_proxy_group=Primary\`select\`[]DIRECT\`!!PROVIDER=extra-nodes
custom_proxy_group=ProviderOnly\`select\`!!PROVIDER=extra-nodes
custom_proxy_group=Auto\`url-test\`.*\`https://example.com/check\`300,,50
ruleset=Primary,[]IP-CIDR,192.0.2.0/24,no-resolve
ruleset=ProviderOnly,[]IP-CIDR,203.0.113.0/24,no-resolve
ruleset=Auto,[]FINAL
`;
const BASE = {
  'mixed-port': 8899,
  'allow-lan': true,
  'bind-address': '0.0.0.0',
  ipv6: true,
  profile: { 'store-selected': false },
  'proxy-providers': {
    'extra-nodes': {
      type: 'inline',
      'health-check': { enable: false },
      payload: [
        {
          name: 'Extra-01',
          type: 'socks5',
          server: '192.0.2.20',
          port: 1080,
          'custom-option': { enabled: true },
          udp: true,
        },
      ],
    },
  },
  proxies: [{ name: 'Stale', type: 'socks5', server: '127.0.0.1', port: 1080 }],
  'proxy-groups': [{ name: 'Stale', type: 'select', proxies: ['DIRECT'] }],
  rules: ['MATCH,REJECT'],
};

function render(options = {}) {
  return ProcessorService.renderOutput({
    targetFormat: 'clash',
    combinedNodeList: 'trojan://example@198.51.100.10:443#Node-01',
    subName: 'Primary',
    config: { UpdateInterval: 86400 },
    builtinOptions: { ruleLevel: 'none', isMeta: true, enableUdp: true },
    templateSource: { kind: 'remote', value: TEMPLATE_URL },
    managedConfigUrl: 'https://example.com/sub',
    storageAdapter: { get: vi.fn().mockResolvedValue(null), put: vi.fn() },
    ...options,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('INI Clash base templates', () => {
  it('preserves native providers and provider-only groups while generating nodes and rules', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url) => {
        if (String(url) === TEMPLATE_URL) return new Response(TEMPLATE);
        if (String(url) === BASE_URL) return new Response(yaml.dump(BASE));
        throw new Error('Unexpected fetch');
      })
    );

    const result = await render();
    const output = yaml.load(result.content);

    expect(output['proxy-providers']).toEqual(BASE['proxy-providers']);
    expect(output['proxy-groups']).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'Primary',
          proxies: ['DIRECT'],
          use: ['extra-nodes'],
        }),
        expect.objectContaining({ name: 'ProviderOnly', use: ['extra-nodes'] }),
      ])
    );
    expect(output['proxy-groups'].find((group) => group.name === 'Auto').proxies).toEqual([
      '🌍 Node-01',
    ]);
    expect(output.proxies.map((proxy) => proxy.name)).toEqual(['🌍 Node-01']);
    expect(output['proxy-groups'].some((group) => group.name === 'Stale')).toBe(false);
    expect(output.rules.slice(0, 3)).toEqual([
      'IP-CIDR,192.0.2.0/24,Primary,no-resolve',
      'IP-CIDR,203.0.113.0/24,ProviderOnly,no-resolve',
      'MATCH,Auto',
    ]);
    expect(output).toMatchObject({
      'mixed-port': 8899,
      'allow-lan': true,
      'bind-address': '0.0.0.0',
      ipv6: true,
      profile: { 'store-selected': false, 'subscription-url': 'https://example.com/sub' },
    });
  });

  it('resolves relative bases and preserves authored rule providers without name collisions', async () => {
    const authoredProvider = {
      type: 'http',
      behavior: 'classical',
      url: 'https://example.com/authored.list',
      path: './ruleset/authored.list',
      format: 'text',
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url) => {
        if (String(url) === TEMPLATE_URL) {
          return new Response(`
[custom]
clash_rule_base=./base.yaml
custom_proxy_group=Primary\`select\`[]DIRECT\`!!PROVIDER=extra-nodes
ruleset=Primary,[]RULE-SET,ai_0,no-resolve
ruleset=Primary,https://example.com/ai.list
ruleset=Primary,[]FINAL
`);
        }
        if (String(url) === BASE_URL) {
          return new Response(yaml.dump({ ...BASE, 'rule-providers': { ai_0: authoredProvider } }));
        }
        throw new Error('Unexpected fetch');
      })
    );

    const output = yaml.load((await render()).content);

    expect(output['rule-providers'].ai_0).toEqual(authoredProvider);
    expect(output['rule-providers'].ai_1.url).toBe('https://example.com/ai.list');
    expect(output.rules.slice(0, 3)).toEqual([
      'RULE-SET,ai_0,Primary,no-resolve',
      'RULE-SET,ai_1,Primary',
      'MATCH,Primary',
    ]);
  });

  it('does not fetch Clash bases or keep provider-only groups for other targets', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(TEMPLATE))
    );

    const result = await render({ targetFormat: 'surge' });

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(result.content).not.toContain('ProviderOnly');
    expect(result.content).not.toContain('!!PROVIDER=');
  });

  it.each(['[]', 'null', 'not-a-mapping'])('rejects invalid base mappings: %s', async (base) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url) => new Response(String(url) === TEMPLATE_URL ? TEMPLATE : base))
    );

    await expect(render()).rejects.toThrow('Clash base template must be a YAML mapping');
  });

  it('rejects missing provider references instead of silently producing a DIRECT-only group', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url) => new Response(String(url) === TEMPLATE_URL ? TEMPLATE : '{}'))
    );

    await expect(render()).rejects.toThrow('Unknown Clash proxy provider: extra-nodes');
  });

  it('blocks private base URLs before making a request', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(TEMPLATE.replace(BASE_URL, 'http://127.0.0.1/base.yaml')))
    );

    await expect(render()).rejects.toThrow('URL host is not allowed');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
