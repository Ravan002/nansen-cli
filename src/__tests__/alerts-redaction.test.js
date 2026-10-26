/**
 * Alerts command - channel credential redaction
 *
 * Slack/Discord webhook URLs, generic webhook URLs and webhook signing secrets
 * grant access to the user's notification channels. Alerts output masks them
 * by default; --reveal returns the raw API response.
 */

import { describe, it, expect, vi } from 'vitest';
import { buildAlertsCommands, redactAlertSecrets, redactUrl, REDACTED } from '../commands/alerts.js';
import { NansenError, ErrorCode } from '../api.js';
import { formatError, runCLI } from '../cli.js';

vi.mock('../telemetry.js', async (importOriginal) => ({
  ...(await importOriginal()),
  trackCommandSucceeded: vi.fn(),
  trackCommandFailed: vi.fn(),
}));

const SLACK = 'https://hooks.slack.com/services/T000/B000/SLACKSECRET';
const DISCORD = 'https://discord.com/api/webhooks/123/DISCORDSECRET';
const WEBHOOK = 'https://example.com/hooks/QUERYPATH?token=QUERYSECRET';
const SIGNING = 'SIGNINGSECRET123456';
const SECRETS = ['SLACKSECRET', 'B000', 'DISCORDSECRET', 'QUERYPATH', 'QUERYSECRET', SIGNING];

function makeAlert(overrides = {}) {
  return {
    id: 'a1',
    name: 'ETH SM',
    type: 'sm-token-flows',
    isEnabled: true,
    data: { chains: ['ethereum'] },
    channels: [
      { type: 'slack', data: { webhookUrl: SLACK } },
      { type: 'discord', data: { webhookUrl: DISCORD } },
      { type: 'webhook', data: { webhookUrl: WEBHOOK, secret: SIGNING } },
      { type: 'telegram', data: { chatId: '5238612255' } },
    ],
    ...overrides,
  };
}

function expectNoSecrets(value) {
  const text = JSON.stringify(value);
  for (const s of SECRETS) expect(text).not.toContain(s);
}

describe('redactUrl', () => {
  it('keeps the identifying path segments of Slack and Discord webhook URLs', () => {
    expect(redactUrl(SLACK)).toBe(`https://hooks.slack.com/services/T000/${REDACTED}`);
    expect(redactUrl(DISCORD)).toBe(`https://discord.com/api/webhooks/123/${REDACTED}`);
    expect(redactUrl('https://ptb.discordapp.com/api/webhooks/123/TOK')).toBe(`https://ptb.discordapp.com/api/webhooks/123/${REDACTED}`);
    expect(redactUrl('https://HOOKS.SLACK.COM/services/T000/B000/X')).toBe(`https://hooks.slack.com/services/T000/${REDACTED}`);
  });

  it('keeps no path segments for other hosts, whatever the channel type', () => {
    expect(redactUrl('https://example.com/tokA/tokB/x')).toBe(`https://example.com/${REDACTED}`);
    expect(redactUrl('https://hooks.slack.com.evil.example/services/T000/B000/X')).toBe(`https://${REDACTED}.evil.example/${REDACTED}`);
  });

  it('drops query, hash and userinfo', () => {
    expect(redactUrl(WEBHOOK)).toBe(`https://example.com/${REDACTED}`);
    expect(redactUrl('https://example.com/#frag')).toBe(`https://example.com/${REDACTED}`);
    expect(redactUrl('https://user:PASSWORD@example.com/x')).toBe(`https://example.com/${REDACTED}`);
  });

  it('masks subdomains of other hosts, which can be the credential', () => {
    expect(redactUrl('https://eo1abc2def3secret.m.pipedream.net')).toBe(`https://${REDACTED}.pipedream.net/${REDACTED}`);
    expect(redactUrl('http://my.n8n.host:5678/webhook/abc')).toBe(`http://${REDACTED}.n8n.host:5678/${REDACTED}`);
    expect(redactUrl('http://10.0.0.5:8080/hook')).toBe(`http://10.0.0.5:8080/${REDACTED}`);
  });

  it('always masks the last path segment', () => {
    expect(redactUrl('https://hooks.slack.com/services/SECRET')).toBe(`https://hooks.slack.com/services/${REDACTED}`);
  });

  it('accepts the JSON-escaped form', () => {
    expect(redactUrl('https:\\/\\/example.com\\/hook\\/SECRET')).toBe(`https://example.com/${REDACTED}`);
  });

  it('masks values that are not URLs entirely', () => {
    expect(redactUrl('not a url')).toBe(REDACTED);
    expect(redactUrl('mailto:someone@example.com')).toBe(REDACTED);
  });
});

describe('redactAlertSecrets', () => {
  it('masks slack, discord and webhook credentials and keeps telegram chat IDs', () => {
    const [slack, discord, webhook, telegram] = redactAlertSecrets(makeAlert()).channels;
    expect(slack).toEqual({ type: 'slack', data: { webhookUrl: `https://hooks.slack.com/services/T000/${REDACTED}` } });
    expect(discord).toEqual({ type: 'discord', data: { webhookUrl: `https://discord.com/api/webhooks/123/${REDACTED}` } });
    expect(webhook).toEqual({ type: 'webhook', data: { webhookUrl: `https://example.com/${REDACTED}`, secret: REDACTED } });
    expect(telegram).toEqual({ type: 'telegram', data: { chatId: '5238612255' } });
  });

  it('leaves the rest of the alert untouched', () => {
    const { channels, ...rest } = redactAlertSecrets(makeAlert());
    const { channels: _, ...original } = makeAlert();
    expect(rest).toEqual(original);
    expect(channels).toHaveLength(4);
  });

  it('does not mutate its input', () => {
    const alert = makeAlert();
    redactAlertSecrets(alert);
    expect(alert).toEqual(makeAlert());
  });

  it('handles arrays and wrapped response shapes', () => {
    expectNoSecrets(redactAlertSecrets([makeAlert(), makeAlert({ id: 'a2' })]));
    expectNoSecrets(redactAlertSecrets({ alerts: [makeAlert()] }));
    expectNoSecrets(redactAlertSecrets({ data: makeAlert() }));
  });

  it('fails closed on unknown channel types and credential-like keys', () => {
    const alert = makeAlert({
      channels: [{ type: 'teams', data: { url: 'https://teams.example.com/hook/TEAMSSECRET', apiKey: 'KEYSECRET', nested: { authToken: 'NESTEDSECRET' }, label: 'ops' } }],
    });
    const { data } = redactAlertSecrets(alert).channels[0];
    expect(data).toEqual({
      url: `https://${REDACTED}.example.com/${REDACTED}`,
      apiKey: REDACTED,
      nested: { authToken: REDACTED },
      label: 'ops',
    });
  });

  it('masks every value of an array under a credential key', () => {
    const alert = makeAlert({ channels: [{ type: 'webhook', data: { webhookUrl: [WEBHOOK, WEBHOOK], secret: [SIGNING] } }] });
    expect(redactAlertSecrets(alert).channels[0].data).toEqual({
      webhookUrl: [`https://example.com/${REDACTED}`, `https://example.com/${REDACTED}`],
      secret: [REDACTED],
    });
  });

  it('tolerates missing, empty and malformed channels', () => {
    expect(redactAlertSecrets(makeAlert({ channels: undefined })).channels).toBeUndefined();
    expect(redactAlertSecrets(makeAlert({ channels: [] })).channels).toEqual([]);
    expect(redactAlertSecrets(makeAlert({ channels: [null, { type: 'slack' }, 'x'] })).channels).toEqual([null, { type: 'slack' }, 'x']);
    expect(redactAlertSecrets(makeAlert({ channels: [{ type: 'slack', data: { webhookUrl: 'garbage' } }] })).channels[0].data.webhookUrl).toBe(REDACTED);
    expect(redactAlertSecrets(null)).toBeNull();
    expect(redactAlertSecrets(undefined)).toBeUndefined();
  });
});

describe('alerts command output redaction', () => {
  const cmd = () => buildAlertsCommands({ log: vi.fn() })['alerts'];

  it('redacts alerts list by default', async () => {
    const api = { alertsList: vi.fn().mockResolvedValue([makeAlert()]) };
    const result = await cmd()(['list'], api, {}, {});
    expectNoSecrets(result);
    expect(result[0].channels[3].data.chatId).toBe('5238612255');
  });

  it('redacts alerts list in the wrapped { alerts } shape', async () => {
    const api = { alertsList: vi.fn().mockResolvedValue({ alerts: [makeAlert()] }) };
    expectNoSecrets(await cmd()(['list'], api, {}, {}));
  });

  it('returns raw channel data for alerts list --reveal', async () => {
    const api = { alertsList: vi.fn().mockResolvedValue([makeAlert()]) };
    const result = await cmd()(['list'], api, { reveal: true }, {});
    expect(result[0].channels).toEqual(makeAlert().channels);
  });

  it('redacts the create response, including the URL the user just passed', async () => {
    const api = { alertsCreate: vi.fn().mockImplementation(async (p) => ({ id: 'new', ...p })) };
    const result = await cmd()(['create'], api, {}, {
      name: 'x', type: 'sm-token-flows', chains: 'ethereum', 'inflow-1h-min': 1,
      slack: SLACK, webhook: WEBHOOK, 'webhook-secret': SIGNING,
    });
    // The request still carries the real values.
    expect(api.alertsCreate.mock.calls[0][0].channels[0].data.webhookUrl).toBe(SLACK);
    expectNoSecrets(result);
  });

  it('redacts the toggle response', async () => {
    const api = { alertsToggle: vi.fn().mockResolvedValue(makeAlert({ isEnabled: false })) };
    expectNoSecrets(await cmd()(['toggle', 'a1'], api, { disabled: true }, {}));
  });

  it('redacts the update response', async () => {
    const api = {
      alertsGet: vi.fn().mockResolvedValue(makeAlert({ data: { chains: ['ethereum'], inflow_1h: { min: 1 } } })),
      alertsUpdate: vi.fn().mockResolvedValue(makeAlert({ name: 'y' })),
    };
    expectNoSecrets(await cmd()(['update', 'a1'], api, {}, { name: 'y' }));
  });

  it.each([
    ['slack', `https://hooks.slack.com/services/T000/${REDACTED}`],
    ['discord', `https://discord.com/api/webhooks/123/${REDACTED}`],
    ['webhook', `https://example.com/${REDACTED}`],
  ])('rejects a redacted --%s value pasted back from output', async (flag, value) => {
    const api = { alertsCreate: vi.fn() };
    await expect(cmd()(['create'], api, {}, { name: 'x', type: 'sm-token-flows', chains: 'ethereum', 'inflow-1h-min': 1, [flag]: value }))
      .rejects.toThrow(`--${flag} looks like a redacted value`);
    expect(api.alertsCreate).not.toHaveBeenCalled();
  });

  it.each(['slack', 'discord', 'webhook', 'webhook-secret'])('rejects --%s passed more than once', async (flag) => {
    const api = { alertsCreate: vi.fn() };
    await expect(cmd()(['create'], api, {}, { name: 'x', type: 'sm-token-flows', chains: 'ethereum', 'inflow-1h-min': 1, webhook: WEBHOOK, [flag]: [WEBHOOK, WEBHOOK] }))
      .rejects.toThrow(`--${flag} can only be passed once`);
    expect(api.alertsCreate).not.toHaveBeenCalled();
  });

  it('rejects a redacted --webhook-secret', async () => {
    const api = { alertsCreate: vi.fn() };
    await expect(cmd()(['create'], api, {}, {
      name: 'x', type: 'sm-token-flows', chains: 'ethereum', 'inflow-1h-min': 1,
      webhook: 'https://example.com/hook', 'webhook-secret': REDACTED.repeat(4),
    })).rejects.toThrow('--webhook-secret looks like a redacted value');
    expect(api.alertsCreate).not.toHaveBeenCalled();
  });
});

describe('alerts command error redaction', () => {
  const cmd = () => buildAlertsCommands({ log: vi.fn() })['alerts'];
  const CREATE = { name: 'x', type: 'sm-token-flows', chains: 'ethereum', 'inflow-1h-min': 1 };

  async function failWith(error, sub, options, flags = {}, method = 'alertsCreate') {
    const api = { [method]: vi.fn().mockRejectedValue(error) };
    try {
      await cmd()(sub, api, flags, options);
    } catch (e) {
      return e;
    }
    throw new Error('expected the command to fail');
  }

  it('masks submitted credentials echoed in an API validation error message and details', async () => {
    const apiError = new NansenError(`Invalid channel: ${SLACK}`, ErrorCode.INVALID_PARAMS, 422, {
      detail: [
        { loc: ['body', 'channels', 0, 'data'], msg: 'unreachable', input: { webhookUrl: WEBHOOK, secret: SIGNING } },
      ],
      requestId: 'req-1',
    });
    const err = await failWith(apiError, ['create'], { ...CREATE, slack: SLACK, webhook: WEBHOOK, 'webhook-secret': SIGNING });
    const printed = formatError(err);
    expectNoSecrets(printed);
    expect(printed.error).toBe(`Invalid channel: https://hooks.slack.com/services/T000/${REDACTED}`);
    expect(printed.details.detail[0].input).toEqual({ webhookUrl: `https://example.com/${REDACTED}`, secret: REDACTED });
    expect(printed).toMatchObject({ code: ErrorCode.INVALID_PARAMS, status: 422, requestId: 'req-1' });
    expect(err).toBeInstanceOf(NansenError);
  });

  it('masks stored channels and known webhook URLs in an alerts list error', async () => {
    const apiError = new NansenError(`Failed to load alert: ${DISCORD} unreachable`, ErrorCode.SERVER_ERROR, 500, {
      alert: makeAlert(),
    });
    const err = await failWith(apiError, ['list'], {}, {}, 'alertsList');
    const printed = formatError(err);
    expectNoSecrets(printed);
    expect(printed.error).toBe(`Failed to load alert: https://discord.com/api/webhooks/123/${REDACTED} unreachable`);
  });

  it('masks credentials in non-NansenError errors and keeps their code', async () => {
    const plain = Object.assign(new Error(`socket hang up posting to ${WEBHOOK}`), { code: 'ECONNRESET', data: { url: WEBHOOK } });
    const err = await failWith(plain, ['create'], { ...CREATE, webhook: WEBHOOK });
    const printed = formatError(err);
    expectNoSecrets(printed);
    expect(printed.code).toBe('ECONNRESET');
  });

  it('does not garble messages with short values that are never sent', async () => {
    const err = await failWith(new Error('unused'), ['create'], { ...CREATE, webhook: 'https://example.com/hook', 'webhook-secret': 'short' });
    expect(err.message).toBe('--webhook-secret must be at least 16 characters');
  });

  it('leaves errors untouched with --reveal', async () => {
    const apiError = new NansenError(`Invalid channel: ${SLACK}`, ErrorCode.INVALID_PARAMS, 422, { input: SLACK });
    const err = await failWith(apiError, ['create'], { ...CREATE, slack: SLACK }, { reveal: true });
    expect(err).toBe(apiError);
  });
});

describe('alerts error redaction of URLs not supplied on this run', () => {
  const cmd = () => buildAlertsCommands({ log: vi.fn() })['alerts'];

  async function listError(error) {
    const api = { alertsList: vi.fn().mockRejectedValue(error) };
    try {
      await cmd()(['list'], api, {}, {});
    } catch (e) {
      return formatError(e);
    }
    throw new Error('expected the command to fail');
  }

  it.each([
    ['versioned Discord', 'https://discord.com/api/v10/webhooks/1/DISCORDSECRET', 'https://discord.com/api/v10/webhooks/****'],
    ['uppercase Slack', 'https://HOOKS.SLACK.COM/services/T000/B000/SLACKSECRET', 'https://hooks.slack.com/services/T000/****'],
    ['http Slack', 'http://hooks.slack.com/services/T000/B000/SLACKSECRET', 'http://hooks.slack.com/services/T000/****'],
    ['generic webhook', 'https://my.n8n.host/webhook/QUERYSECRET', 'https://****.n8n.host/****'],
  ])('masks a %s URL quoted in an error message', async (_label, url, masked) => {
    const printed = await listError(new NansenError(`existing channel ${url} failed`, ErrorCode.SERVER_ERROR, 500));
    expect(printed.error).toBe(`existing channel ${masked} failed`);
  });

  it('masks a JSON-escaped URL in a raw error body', async () => {
    const printed = await listError(new NansenError('bad', ErrorCode.SERVER_ERROR, 500, {
      body: '{"input":"https:\\/\\/example.com\\/hook\\/QUERYSECRET"}',
    }));
    expectNoSecrets(printed);
  });

  it('keeps Nansen URLs in error text', async () => {
    const printed = await listError(new NansenError('See https://docs.nansen.ai/getting-started/error-handling', ErrorCode.SERVER_ERROR, 500));
    expect(printed.error).toBe('See https://docs.nansen.ai/getting-started/error-handling');
  });

  it('drops details it cannot walk instead of failing open or crashing', async () => {
    const details = { input: SLACK };
    details.self = details;
    const printed = await listError(new NansenError('bad', ErrorCode.SERVER_ERROR, 500, details));
    expect(printed).toMatchObject({ error: 'bad', code: ErrorCode.SERVER_ERROR, status: 500 });
    expect(printed.details).toBeUndefined();
  });
});

describe('alerts redaction through the CLI output pipeline', () => {
  function MockAPI() {
    return {
      alertsList: vi.fn().mockResolvedValue([makeAlert()]),
      alertsCreate: vi.fn().mockRejectedValue(new NansenError(`Invalid channel: ${SLACK}`, ErrorCode.INVALID_PARAMS, 422, { input: { webhookUrl: WEBHOOK, secret: SIGNING } })),
    };
  }

  async function run(args) {
    const out = [];
    const err = [];
    await runCLI(args, { NansenAPIClass: MockAPI, output: m => out.push(m), errorOutput: m => err.push(m), exit: () => {}, isTTY: false, env: {} });
    return out.join('\n') + err.join('\n');
  }

  it.each([
    [[]],
    [['--pretty']],
    [['--stream']],
    [['--table']],
    [['--fields', 'channels']],
    [['--format', 'csv']],
  ])('alerts list %j prints no credentials', async (extra) => {
    const text = await run(['alerts', 'list', ...extra]);
    expect(text).not.toBe('');
    for (const s of SECRETS) expect(text).not.toContain(s);
  });

  it('alerts list --reveal prints the credentials', async () => {
    expect(await run(['alerts', 'list', '--reveal'])).toContain('SLACKSECRET');
  });

  it('a failed alerts create prints an error envelope with no credentials', async () => {
    const text = await run(['alerts', 'create', '--name', 'x', '--type', 'sm-token-flows', '--chains', 'ethereum', '--inflow-1h-min', '1',
      '--slack', SLACK, '--webhook', WEBHOOK, '--webhook-secret', SIGNING]);
    expect(text).toContain('INVALID_PARAMS');
    for (const s of SECRETS) expect(text).not.toContain(s);
  });
});

describe('alerts error redaction of credentials in the request payload', () => {
  const cmd = () => buildAlertsCommands({ log: vi.fn() })['alerts'];
  const CREATE = { name: 'x', type: 'sm-token-flows', chains: 'ethereum', 'inflow-1h-min': 1, telegram: '123' };

  async function fail(api, sub, options) {
    try {
      await cmd()(sub, api, {}, options);
    } catch (e) {
      return formatError(e);
    }
    throw new Error('expected the command to fail');
  }

  it('masks a non-URL secret sent through --data and echoed in the error message', async () => {
    const api = { alertsCreate: vi.fn().mockRejectedValue(new NansenError(`rejected secret ${SIGNING}`, ErrorCode.INVALID_PARAMS, 422)) };
    const printed = await fail(api, ['create'], { ...CREATE, data: JSON.stringify({ webhookSecret: SIGNING }) });
    expect(api.alertsCreate.mock.calls[0][0].data.webhookSecret).toBe(SIGNING);
    expect(printed.error).toBe(`rejected secret ${REDACTED}`);
  });

  it('masks a credential merged into an update from the existing alert data', async () => {
    const api = {
      alertsGet: vi.fn().mockResolvedValue({ type: 'sm-token-flows', data: { chains: ['ethereum'], inflow_1h: { min: 1 }, callbackToken: SIGNING } }),
      alertsUpdate: vi.fn().mockRejectedValue(new NansenError(`bad callbackToken ${SIGNING}`, ErrorCode.INVALID_PARAMS, 422)),
    };
    const printed = await fail(api, ['update', 'a1'], { 'inflow-1h-min': 2 });
    expect(printed.error).toBe(`bad callbackToken ${REDACTED}`);
  });

  it('does not mask alert filters whose keys merely contain "token"', async () => {
    const api = { alertsCreate: vi.fn().mockRejectedValue(new NansenError('Unknown sector Stablecoins for 0xabcdef0123', ErrorCode.INVALID_PARAMS, 422)) };
    const printed = await fail(api, ['create'], {
      ...CREATE,
      data: JSON.stringify({ inclusion: { tokenSectors: ['Stablecoins'], tokens: [{ address: '0xabcdef0123', chain: 'ethereum' }] } }),
    });
    expect(printed.error).toBe('Unknown sector Stablecoins for 0xabcdef0123');
  });
});
