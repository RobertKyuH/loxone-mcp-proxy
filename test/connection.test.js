import test from 'node:test';
import assert from 'node:assert/strict';
import { Connection, readSSE, backoff } from '../src/connection.js';
import { AuthError } from '../src/loxoneAuth.js';
import { resp } from './helpers.js';

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const resolverStub = () => ({ resolve: async () => 'https://entry.x:1', invalidate() {} });
const nullCache = () => ({ load: () => null, save() {} });

function token(overrides = {}) {
  return {
    entryOrigin: 'https://entry.x:1', resource: 'https://relay.x/mcp', clientId: 'CID',
    accessToken: 'AT', refreshToken: 'RT', tokenType: 'Bearer', expiresAt: Date.now() + 3600_000, ...overrides,
  };
}

test('ensureAuth reuses a valid cached token (no auth call)', async () => {
  const cache = { load: () => token(), save() {} };
  let authorized = false;
  const auth = { fetch: async () => {}, authorize: async () => { authorized = true; return token(); }, refresh: async () => { throw new Error('nope'); } };
  const c = new Connection({ resolver: resolverStub(), auth, cache, log: silent, fetchImpl: async () => {} });
  await c.ensureAuth();
  assert.equal(authorized, false);
  assert.equal(c.state.accessToken, 'AT');
});

test('ensureAuth refreshes an expired token', async () => {
  const cache = { load: () => token({ expiresAt: Date.now() - 1000 }), save() {} };
  let refreshed = false;
  const auth = {
    fetch: async () => {},
    authorize: async () => { throw new Error('should not full-auth'); },
    refresh: async () => { refreshed = true; return { accessToken: 'AT2', refreshToken: 'RT2', tokenType: 'Bearer', expiresAt: Date.now() + 3600_000 }; },
  };
  const c = new Connection({ resolver: resolverStub(), auth, cache, log: silent, fetchImpl: async () => {} });
  await c.ensureAuth();
  assert.equal(refreshed, true);
  assert.equal(c.state.accessToken, 'AT2');
});

test('ensureAuth falls back to full auth when refresh fails', async () => {
  const cache = { load: () => token({ expiresAt: Date.now() - 1000 }), save() {} };
  const auth = { fetch: async () => {}, authorize: async () => token({ accessToken: 'FRESH' }), refresh: async () => { throw new Error('refresh boom'); } };
  const c = new Connection({ resolver: resolverStub(), auth, cache, log: silent, fetchImpl: async () => {} });
  await c.ensureAuth();
  assert.equal(c.state.accessToken, 'FRESH');
});

test('_fullAuth does not re-resolve after an AuthError (entry was reachable, just rejected)', async () => {
  let invalidated = false;
  const resolver = { resolve: async () => 'https://entry.x:1', invalidate() { invalidated = true; } };
  let authCalls = 0;
  const auth = {
    fetch: async () => {},
    authorize: async () => {
      authCalls++;
      if (authCalls === 1) throw new AuthError('client registration: HTTP 500', { status: 500 });
      return token({ accessToken: 'RETRY-OK' });
    },
    refresh: async () => { throw new Error('no refresh'); },
  };
  const c = new Connection({ resolver, auth, cache: nullCache(), log: silent, fetchImpl: async () => {}, maxAuthAttempts: 2 });
  await c.ensureAuth();
  assert.equal(c.state.accessToken, 'RETRY-OK');
  assert.equal(invalidated, false, 'a registration/login rejection should not invalidate a perfectly reachable relay entry');
});

test('_fullAuth re-resolves after a non-AuthError failure (entry may be stale/unreachable)', async () => {
  let invalidated = false;
  const resolver = { resolve: async () => 'https://entry.x:1', invalidate() { invalidated = true; } };
  let authCalls = 0;
  const auth = {
    fetch: async () => {},
    authorize: async () => {
      authCalls++;
      if (authCalls === 1) throw new Error('ECONNREFUSED');
      return token({ accessToken: 'RETRY-OK2' });
    },
    refresh: async () => { throw new Error('no refresh'); },
  };
  const c = new Connection({ resolver, auth, cache: nullCache(), log: silent, fetchImpl: async () => {}, maxAuthAttempts: 2 });
  await c.ensureAuth();
  assert.equal(c.state.accessToken, 'RETRY-OK2');
  assert.equal(invalidated, true, 'a network-level failure reaching the entry should trigger a fresh resolve');
});

test('send(initialize) parses SSE and captures the session id + protocol', async () => {
  const sse = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"lox"}}}\n\n';
  const fetchImpl = async () => resp({ status: 200, headers: { 'content-type': 'text/event-stream', 'mcp-session-id': 'SID1' }, body: sse });
  const auth = { fetch: fetchImpl, authorize: async () => token(), refresh: async () => {} };
  const c = new Connection({ resolver: resolverStub(), auth, cache: nullCache(), log: silent, fetchImpl });
  const msgs = await c.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(msgs.length, 1);
  assert.equal(c.sessionId, 'SID1');
  assert.equal(c.protocolVersion, '2025-06-18');
});

test('send retries after a 401 by re-authenticating', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    if (calls === 1) return resp({ status: 401, body: '{"error":"unauthorized"}' });
    return resp({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":2,"result":{}}' });
  };
  let auths = 0;
  const auth = { fetch: fetchImpl, authorize: async () => { auths++; return token({ accessToken: 'AT' + auths }); }, refresh: async () => { throw new Error('no refresh'); } };
  const c = new Connection({ resolver: resolverStub(), auth, cache: nullCache(), log: silent, fetchImpl });
  c.state = token();
  const msgs = await c.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal(msgs[0].id, 2);
  assert.ok(calls >= 2 && auths >= 1);
});

test('send re-resolves on a network error', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    if (calls === 1) throw new Error('ECONNREFUSED');
    return resp({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":3,"result":{}}' });
  };
  let invalidated = false;
  const resolver = { resolve: async () => 'https://entry.x:1', invalidate() { invalidated = true; } };
  const auth = { fetch: fetchImpl, authorize: async () => token(), refresh: async () => { throw new Error('no'); } };
  const c = new Connection({ resolver, auth, cache: nullCache(), log: silent, fetchImpl });
  c.state = token();
  const msgs = await c.send({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  assert.equal(msgs[0].id, 3);
  assert.ok(invalidated);
});

test('readSSE parses multiple events and ignores keep-alives', async () => {
  const body = ': keep-alive\n\ndata: {"a":1}\n\ndata: {"b":2}\n\n';
  const msgs = await readSSE(resp({ body }));
  assert.deepEqual(msgs, [{ a: 1 }, { b: 2 }]);
});

test('send replays initialize when the session was lost', async () => {
  const posts = [];
  const fetchImpl = async (url, opts) => {
    const b = JSON.parse(opts.body);
    posts.push(b.method);
    if (b.method === 'initialize') return resp({ status: 200, headers: { 'content-type': 'application/json', 'mcp-session-id': 'NEWSID' }, body: '{"jsonrpc":"2.0","id":1,"result":{}}' });
    return resp({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":9,"result":{}}' });
  };
  const auth = { fetch: fetchImpl, authorize: async () => token(), refresh: async () => {} };
  const c = new Connection({ resolver: resolverStub(), auth, cache: nullCache(), log: silent, fetchImpl });
  c.state = token();
  c.initMessage = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} };
  c.sessionId = null;
  const msgs = await c.send({ jsonrpc: '2.0', id: 9, method: 'tools/list' });
  assert.ok(posts.includes('initialize'));
  assert.equal(c.sessionId, 'NEWSID');
  assert.equal(msgs[0].id, 9);
});

test('backoff grows and is capped at 8s', () => {
  assert.ok(backoff(1) <= backoff(2));
  assert.ok(backoff(20) <= 8000);
});

test('direct mode: a cached token for a different entry is discarded', () => {
  const cache = { load: () => token({ entryOrigin: 'https://old-relay.x:9' }), save() {} };
  const resolver = { fixedEntry: 'https://lan.x', resolve: async () => 'https://lan.x', invalidate() {} };
  const c = new Connection({ resolver, auth: {}, cache, log: silent, fetchImpl: async () => {} });
  assert.equal(c.state, null);
});

test('direct mode: a cached token for the same entry is kept', () => {
  const cache = { load: () => token({ entryOrigin: 'https://lan.x' }), save() {} };
  const resolver = { fixedEntry: 'https://lan.x', resolve: async () => 'https://lan.x', invalidate() {} };
  const c = new Connection({ resolver, auth: {}, cache, log: silent, fetchImpl: async () => {} });
  assert.equal(c.state.accessToken, 'AT');
});

test('_fullAuth stops immediately on a fatal AuthError (rejected credentials)', async () => {
  let authCalls = 0;
  const auth = {
    fetch: async () => {},
    authorize: async () => { authCalls++; throw new AuthError('login was rejected (form re-rendered)', { fatal: true }); },
    refresh: async () => { throw new Error('no refresh'); },
  };
  const c = new Connection({ resolver: resolverStub(), auth, cache: nullCache(), log: silent, fetchImpl: async () => {}, maxAuthAttempts: 6 });
  await assert.rejects(() => c.ensureAuth(), /login was rejected/);
  assert.equal(authCalls, 1, 'every retry is another failed login counted by the Miniserver lockout');
});
