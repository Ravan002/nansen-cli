/**
 * Alerts command - channel credential redaction
 *
 * Slack/Discord webhook URLs, generic webhook URLs and webhook signing secrets
 * grant access to the user's notification channels. Alerts output masks them
 * by default; --reveal returns the raw API response.
 */

import { describe, it, expect, vi } from 'vitest';
import { buildAlertsCommands, redactAlertSecrets, redactUrl, REDACTED } from '../commands/alerts.js';

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
  it('keeps the origin and the requested leading path segments', () => {
    expect(redactUrl(SLACK, 2)).toBe(`https://hooks.slack.com/services/T000/${REDACTED}`);
    expect(redactUrl(DISCORD, 3)).toBe(`https://discord.com/api/webhooks/123/${REDACTED}`);
  });

  it('keeps only the origin by default and drops query and hash', () => {
    expect(redactUrl(WEBHOOK)).toBe(`https://example.com/${REDACTED}`);
    expect(redactUrl('https://example.com/#frag')).toBe(`https://example.com/${REDACTED}`);
  });

  it('always masks the last path segment even when asked to keep more', () => {
    expect(redactUrl('https://hooks.slack.com/services/SECRET', 2)).toBe(`https://hooks.slack.com/services/${REDACTED}`);
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
      url: `https://teams.example.com/${REDACTED}`,
      apiKey: REDACTED,
      nested: { authToken: REDACTED },
      label: 'ops',
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

  it('rejects a redacted --webhook-secret', async () => {
    const api = { alertsCreate: vi.fn() };
    await expect(cmd()(['create'], api, {}, {
      name: 'x', type: 'sm-token-flows', chains: 'ethereum', 'inflow-1h-min': 1,
      webhook: 'https://example.com/hook', 'webhook-secret': REDACTED.repeat(4),
    })).rejects.toThrow('--webhook-secret looks like a redacted value');
    expect(api.alertsCreate).not.toHaveBeenCalled();
  });
});
