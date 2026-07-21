import crypto from 'crypto';
import http from 'http';
import https from 'https';

export interface DlklapConfig {
  ip: string;
  deviceId: string;
  terminalUUID: string;
  cloudUsername: string;
  cloudPassword: string;
  accountId?: string;      // taken from login if omitted
}

export interface DeviceInfo {
  lock_status: number;
  battery_percentage?: number;
  at_low_battery?: boolean;
  rssi?: number;
  [k: string]: unknown;
}

type Json = any;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function sha(...parts: Buffer[]): Buffer {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}
function pkcs7pad(b: Buffer): Buffer {
  const n = 16 - (b.length % 16);
  return Buffer.concat([b, Buffer.alloc(n, n)]);
}
function pkcs7unpad(b: Buffer): Buffer {
  return b.subarray(0, b.length - b[b.length - 1]);
}
function aesEncrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const c = crypto.createCipheriv('aes-128-cbc', key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}
function aesDecrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(data), d.final()]);
}

// Robustly pull the first complete JSON object out of the decrypted body
// (there is a ~4-byte prefix before the '{').
function extractJson(buf: Buffer): Json {
  const s = buf.toString('utf8');
  const start = s.indexOf('{');
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
    } else if (ch === '"') inStr = true;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return JSON.parse(s.slice(start, i + 1));
  }
  throw new Error('no complete JSON object in response');
}

// Raw HTTP(S) POST via node's http/https. We do NOT use global fetch: undici
// mangles the DL100 handshake (the 33-byte binary hs0 body) and the cloud then
// rejects the secret with 15033. node:http reproduces step9.py exactly.
function req(
  urlStr: string,
  opts: { headers?: Record<string, string>; body?: Buffer | string | null; rejectUnauthorized?: boolean } = {},
): Promise<{ status: number; headers: http.IncomingHttpHeaders; buf: Buffer }> {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    const body = opts.body ?? null;
    if (body != null) headers['Content-Length'] = String(Buffer.byteLength(body as Buffer));
    const r = lib.request(
      {
        hostname: u.hostname,
        port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method: 'POST',
        headers,
        rejectUnauthorized: opts.rejectUnauthorized ?? true,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, buf: Buffer.concat(chunks) }));
      },
    );
    r.on('error', reject);
    if (body != null) r.write(body);
    r.end();
  });
}

// One live DLKLAP session (single handshake0, incrementing seq).
class Session {
  private seq: number;
  constructor(
    private ip: string,
    private lsk: Buffer,
    private ldk: Buffer,
    private ivb: Buffer,
    seq0: number,
    private cookie: string,
  ) { this.seq = seq0; }

  call(requests: Json[]): Promise<Json> {
    return this.request({ method: 'multipleRequest', params: { requests } });
  }

  private async request(plaintext: Json): Promise<Json> {
    this.seq += 1;
    const seqB = Buffer.alloc(4); seqB.writeUInt32BE(this.seq >>> 0);
    const iv = Buffer.concat([this.ivb, seqB]);          // 12 + 4 = 16
    const pt = Buffer.from(JSON.stringify(plaintext), 'utf8');
    const ct = aesEncrypt(this.lsk, iv, pkcs7pad(pt));
    const mac = sha(this.ldk, seqB, ct);                 // KLAP seq4 form
    const body = Buffer.concat([mac, ct]);
    const res = await req(`http://${this.ip}:80/app/request?seq=${this.seq}`, {
      headers: {
        Referer: `http://${this.ip}:80/`,
        Accept: 'application/json',
        requestByApp: 'true',
        'Content-Type': 'text/plain',
        Cookie: this.cookie,
      },
      body,
    });
    if (res.status !== 200) throw new Error(`/app/request HTTP ${res.status} (seq=${this.seq})`);
    const dec = pkcs7unpad(aesDecrypt(this.lsk, iv, res.buf.subarray(32)));
    return extractJson(dec);
  }
}

export class DlklapApi {
  private token?: string;
  private accountId?: string;
  private _session?: Session;   // cached session; cleared on any failure to force re-handshake

  constructor(
    private cfg: DlklapConfig,
    private log: { debug: (m: string) => void; warn: (m: string) => void; error: (m: string) => void },
  ) {
    if (cfg.accountId) this.accountId = cfg.accountId;
  }

  async getDeviceInfo(): Promise<DeviceInfo> {
    return this.withSession(async (s) =>
      (await s.call([{ method: 'getDeviceInfo' }])).result.responses[0].result);
  }

  async setLock(locked: boolean): Promise<void> {
    await this.withSession(async (s) => {
      const r = await s.call([{ method: 'setLockStatus',
        params: { lock_status: locked ? 0 : 1, sa_user_id: 'local_1' } }]);  // 0 = lock (bolt out), 1 = unlock (bolt in)
      const resp = r.result?.responses?.[0];
      if (resp?.error_code !== 0) throw new Error(`setLockStatus failed: ${JSON.stringify(r)}`);
    });
  }

  // Serialize all sessions. A second handshake0 while another is in flight
  // rotates the device state and invalidates the first (cloud returns 15033).
  private chain: Promise<unknown> = Promise.resolve();

  private withSession<T>(fn: (s: Session) => Promise<T>): Promise<T> {
    const task = this.chain.then(() => this.runSession(fn), () => this.runSession(fn));
    this.chain = task.then(() => undefined, () => undefined);   // keep chain alive
    return task;
  }

  private async runSession<T>(fn: (s: Session) => Promise<T>): Promise<T> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await this.ensureToken();
        // Reuse cached session to skip the cloud control-key round-trip on back-to-back ops.
        // ensureAwake() removed: lock responds to handshake0 directly (~1.1s cold, verified 2026-07-21).
        if (!this._session) {
          this._session = await this.handshake();
          this.log.debug('New DLKLAP session established.');
        }
        return await fn(this._session);
      } catch (e) {
        lastErr = e;
        this._session = undefined;      // force re-handshake on retry
        this.token = undefined;         // force re-login on retry
        const cause = (e as any)?.cause;
        const causeStr = cause ? ` | cause: ${cause.code ?? ''} ${cause.message ?? cause}` : '';
        this.log.warn(`session attempt ${attempt + 1} failed: ${(e as Error).message}${causeStr}`);
        await sleep(500);
      }
    }
    throw lastErr;
  }

  private async ensureToken(): Promise<void> {
    if (this.token) return;
    const body = { method: 'login', params: {
      appType: 'Tapo_Android', cloudUserName: this.cfg.cloudUsername,
      cloudPassword: this.cfg.cloudPassword, terminalUUID: this.cfg.terminalUUID,
      refreshTokenNeeded: false } };
    const res = await req('https://wap.tplinkcloud.com/', {
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const r = JSON.parse(res.buf.toString('utf8')) as Json;
    if (r.error_code !== 0) throw new Error(`login failed: ${JSON.stringify(r)}`);
    this.token = r.result.token;
    this.accountId = this.accountId ?? String(r.result.accountId);
  }

  // handshake0 -> cloud control-key -> handshake1/2 -> derive session keys
  private async handshake(): Promise<Session> {
    const base = `http://${this.cfg.ip}:80`;
    const localHeaders = { 'Content-Type': 'text/plain', Referer: `${base}/` };

    // handshake0 (33-byte body = sha((rand4hex+accountId).upper()) + ROLE=0)
    const rand4 = crypto.randomBytes(4);
    const digest = sha(Buffer.from((rand4.toString('hex') + this.accountId).toUpperCase(), 'ascii'));
    const hs0 = await req(`${base}/app/handshake0`, {
      headers: localHeaders,
      body: Buffer.concat([digest.subarray(0, 32), Buffer.from([0])]),
    });
    if (hs0.status !== 200) throw new Error(`handshake0 HTTP ${hs0.status}`);
    const secret = hs0.buf.toString('utf8').trim();

    // cloud control-key (bound to THIS handshake0).
    // TP-Link's app-server uses a private CA ("self-signed" to public roots), so
    // this single call skips TLS verification via node:https. The login call
    // above (which carries the account password) stays fully verified.
    const ckRaw = await req(
      `https://use1-app-server.iot.i.tplinknbu.com/v1/things/${this.cfg.deviceId}/control-key`,
      {
        headers: {
          Authorization: `ut|${this.token}`,
          'app-cid': `app:Tapo_Android:${this.cfg.terminalUUID}`,
          'App-Type': 'Tapo_Android', 'x-app-name': 'Tapo_Android',
          UUID: this.cfg.terminalUUID, 'Terminal-Id': this.cfg.terminalUUID, 'x-term-id': this.cfg.terminalUUID,
          Platform: 'ANDROID', 'X-App-Os': 'android', 'Content-Type': 'application/json',
        },
        body: JSON.stringify({ secret, random: rand4.toString('hex').toUpperCase() }),
        rejectUnauthorized: false,   // TP-Link private CA
      },
    );
    const ckRes = JSON.parse(ckRaw.buf.toString('utf8')) as Json;
    const ckObj = ckRes.result ?? ckRes.data ?? ckRes;
    const controlKey: string | undefined = ckObj.controlKey ?? ckObj.control_key;
    if (!controlKey) throw new Error(`control-key missing: ${JSON.stringify(ckRes)}`);

    // handshake1 (verify server) + capture TP_SESSIONID cookie
    const ck = Buffer.from(controlKey.toUpperCase(), 'ascii');   // 64 ASCII bytes, owner raw
    const lmk = sha(ck);
    const L = crypto.randomBytes(16);
    const hs1 = await req(`${base}/app/handshake1`, {
      headers: localHeaders,
      body: Buffer.concat([L, sha(Buffer.concat([L, ck]))]),
    });
    if (hs1.status !== 200) throw new Error(`handshake1 HTTP ${hs1.status}`);
    const setCookie = (hs1.headers['set-cookie'] ?? []).join('; ');
    const m = /TP_SESSIONID=[^;]+/.exec(setCookie);
    if (!m) throw new Error('no TP_SESSIONID cookie on handshake1');
    const cookie = m[0];
    const R = hs1.buf.subarray(0, 16);
    const serverProof = hs1.buf.subarray(16, 48);
    if (!sha(Buffer.concat([L, R, lmk])).equals(serverProof)) {
      throw new Error('handshake1 server proof mismatch (bad control key / stale hs0?)');
    }

    // handshake2
    const hs2 = await req(`${base}/app/handshake2`, {
      headers: { ...localHeaders, Cookie: cookie },
      body: sha(Buffer.concat([R, L, lmk])),
    });
    if (hs2.status !== 200) throw new Error(`handshake2 HTTP ${hs2.status}`);

    // derive session keys
    const kdf = (tag: string) => sha(Buffer.concat([Buffer.from(tag, 'ascii'), L, R, lmk]));
    const lsk = kdf('lsk').subarray(0, 16);
    const ldk = kdf('ldk').subarray(0, 28);
    const ivFull = kdf('iv');
    const ivb = ivFull.subarray(0, 12);
    const seq0 = ivFull.readUInt32BE(28) & 0x7fffffff;
    return new Session(this.cfg.ip, lsk, ldk, ivb, seq0, cookie);
  }
}
