const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const crypto = require('crypto');

process.env.DB_PATH = ':memory:';

const app = require('../src/server');
const { getDb } = require('../src/db');

let server;
let baseUrl;

function request(method, path, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers
    };

    if (data && (method === 'POST' || method === 'PUT')) {
      if (typeof data === 'object' && !Buffer.isBuffer(data)) {
        if (headers['Content-Type'] === 'application/json') {
          data = JSON.stringify(data);
        } else {
          data = new URLSearchParams(data).toString();
          options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
      }
      options.headers['Content-Length'] = Buffer.byteLength(data);
    }

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          body = JSON.parse(body);
        } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', reject);
    if (data && (method === 'POST' || method === 'PUT')) req.write(data);
    req.end();
  });
}

function basicAuth(client) {
  return 'Basic ' + Buffer.from(client.client_id + ':' + client.client_secret).toString('base64');
}

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://localhost:${server.address().port}`;
      resolve();
    });
  });
});

test.after(() => server.close());

async function setupClientAndTokens() {
  const reg = await request('POST', '/register', {
    client_name: 'Token Events Test Client',
    client_type: 'confidential',
    redirect_uris: ['http://localhost:8080/callback'],
    grant_types: ['authorization_code', 'refresh_token']
  }, { 'Content-Type': 'application/json' });
  assert.strictEqual(reg.status, 201);
  const client = reg.body;

  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const consent = await request('POST', '/authorize/consent', {
    client_id: client.client_id,
    redirect_uri: 'http://localhost:8080/callback',
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    username: 'alice',
    action: 'allow'
  });
  const code = new URL(consent.headers.location).searchParams.get('code');

  const tokenRes = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'http://localhost:8080/callback',
    code_verifier: verifier
  }, { Authorization: basicAuth(client) });
  assert.strictEqual(tokenRes.status, 200);

  return { client, code, tokens: tokenRes.body };
}

test('事件写入：code 消费、轮换、无效 token 拒绝均产生记录且按时间返回', async () => {
  const { client, tokens } = await setupClientAndTokens();

  // 无效 token 被拒绝
  const badRefresh = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: 'refresh_not_exist'
  }, { Authorization: basicAuth(client) });
  assert.strictEqual(badRefresh.status, 400);

  // 成功轮换
  const rotated = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token
  }, { Authorization: basicAuth(client) });
  assert.strictEqual(rotated.status, 200);

  const res = await request('GET', '/token-events', null, { Authorization: basicAuth(client) });
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(res.body.events));

  const types = res.body.events.map(e => e.event_type);
  assert.ok(types.includes('authorization_code_consumed'));
  assert.ok(types.includes('invalid_token_rejected'));
  assert.ok(types.includes('refresh_token_rotated'));

  for (const event of res.body.events) {
    assert.ok(Number.isInteger(event.id));
    assert.ok(Number.isInteger(event.created_at));
  }
  const timestamps = res.body.events.map(e => e.created_at);
  const sorted = [...timestamps].sort((a, b) => a - b);
  assert.deepStrictEqual(timestamps, sorted);
});

test('筛选：按 event_type 过滤且未知类型返回 400', async () => {
  const { client } = await setupClientAndTokens();

  const filtered = await request('GET', '/token-events?event_type=authorization_code_consumed', null, {
    Authorization: basicAuth(client)
  });
  assert.strictEqual(filtered.status, 200);
  assert.ok(filtered.body.events.length > 0);
  for (const event of filtered.body.events) {
    assert.strictEqual(event.event_type, 'authorization_code_consumed');
  }

  const noneMatched = await request('GET', '/token-events?event_type=refresh_token_rotated', null, {
    Authorization: basicAuth(client)
  });
  assert.strictEqual(noneMatched.status, 200);
  for (const event of noneMatched.body.events) {
    assert.strictEqual(event.event_type, 'refresh_token_rotated');
  }

  const unknown = await request('GET', '/token-events?event_type=not_a_type', null, {
    Authorization: basicAuth(client)
  });
  assert.strictEqual(unknown.status, 400);
  assert.strictEqual(unknown.body.error, 'invalid_request');
});

test('敏感值不落库：记录仅含 id/事件类型/时间，且无认证不可访问', async () => {
  const { client, code, tokens } = await setupClientAndTokens();

  const rows = getDb().prepare('SELECT * FROM token_events').all();
  assert.ok(rows.length > 0);
  for (const row of rows) {
    assert.deepStrictEqual(Object.keys(row).sort(), ['created_at', 'event_type', 'id']);
    const serialized = JSON.stringify(row);
    assert.ok(!serialized.includes(code));
    assert.ok(!serialized.includes(tokens.access_token));
    assert.ok(!serialized.includes(tokens.refresh_token));
  }

  const noAuth = await request('GET', '/token-events');
  assert.strictEqual(noAuth.status, 401);
  assert.strictEqual(noAuth.body.error, 'invalid_client');

  const wrongSecret = await request('GET', '/token-events', null, {
    Authorization: 'Basic ' + Buffer.from(client.client_id + ':wrong-secret').toString('base64')
  });
  assert.strictEqual(wrongSecret.status, 401);
});
