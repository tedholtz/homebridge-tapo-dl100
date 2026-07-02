import crypto from 'crypto';
import net from 'net';
import https from 'https';

export interface DlklapConfig {
  ip: string;
  deviceId: string;
  terminalUUID: string;
  cloudUsername: string;
  cloudPassword: string;
  accountId?: string;      // taken from login if omitted
  insecureTLS?: boolean;   // DEBUG ONLY (e.g. mitmproxy CA present)
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

// TCP-connect wake probe (mirrors `nc` / socket.create_connection).
function tcpProbe(ip: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = new net.Socket();
    const done = (v: boolean) => { s.destroy(); resolve(v); };
    s.setTimeout(timeoutMs);
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
    s.connect(port, ip);
  });
}

// POST JSON over HTTPS with a per-call TLS trust setting. Node's global fetch
// can't relax TLS without pulling in undici, so we use node:https here. Needed
// because TP-Link's app-server presents a private-CA ("self-signed") chain.
function httpsPostJson(
  url: string,
  headers: Record<string, string>,
  bodyObj: unknown,
  rejectUnauthorized: boolean,
): Promise<any> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = Buffer.from(JSON.stringify(bodyObj), 'utf8');
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: 'POST',
        headers: { ...headers, 'Content-Length': String(data.length) },
        rejectUnauthorized,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          try { resolve(JSON.parse(text)); }
          catch { reject(new Error(`bad JSON (HTTP ${res.statusCode}): ${text.slice(0, 200)}`)); }
        });
      },
    );
    req.on('error', reject);
    req.write(data);
    req.end();
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
    const res = await fetch(`http://${this.ip}:80/app/request?seq=${this.seq}`, {
      method: 'POST',
      headers: {
        'Referer': `http://${this.ip}:80/`,
        'Accept': 'application/json',
        'requestByApp': 'true',
        'Content-Type': 'text/plain',
        'Cookie': this.cookie,
      },
      body: new Uint8Array(body),
    });
    if (res.status !== 200) throw new Error(`/app/request HTTP ${res.status} (seq=${this.seq})`);
    const data = Buffer.from(await res.arrayBuffer());
    const dec = pkcs7unpad(aesDecrypt(this.lsk, iv, data.subarray(32)));
    return extractJson(dec);
  }
}

export class DlklapApi {
  private token?: string;
  private accountId?: string;

  constructor(
    private cfg: DlklapConfig,
    private log: { debug: (m: string) => void; warn: (m: string) => void; error: (m: string) => void },
  ) {
    if (cfg.accountId) this.accountId = cfg.accountId;
    if (cfg.insecureTLS) {
      this.log.warn('insecureTLS enabled — TLS verification disabled (debug only!)');
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    }
  }

  async getDeviceInfo(): Promise<DeviceInfo> {
    return this.withSession(async (s) =>
      (await s.call([{ method: 'getDeviceInfo' }])).result.responses[0].result);
  }

  async setLock(locked: boolean): Promise<void> {
    await this.withSession(async (s) => {
      const r = await s.call([{ method: 'setLockStatus',
        params: { lock_status: locked ? 1 : 0, sa_user_id: 'local_1' } }]);
      const resp = r.result?.responses?.[0];
      if (resp?.error_code !== 0) throw new Error(`setLockStatus failed: ${JSON.stringify(r)}`);
    });
  }

  private async withSession<T>(fn: (s: Session) => Promise<T>): Promise<T> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await this.ensureToken();
        await this.ensureAwake();
        const session = await this.handshake();
        return await fn(session);
      } catch (e) {
        lastErr = e;
        const cause = (e as any)?.cause;
        const causeStr = cause ? ` | cause: ${cause.code ?? ''} ${cause.message ?? cause}` : '';
        this.log.warn(`session attempt ${attempt + 1} failed: ${(e as Error).message}${causeStr}`);
        this.token = undefined;         // force re-login + fresh handshake
        await sleep(500);
      }
    }
    throw lastErr;
  }

  private async ensureAwake(): Promise<void> {
    for (let i = 0; i < 40; i++) {
      if (await tcpProbe(this.cfg.ip, 80, 600)) return;
      await sleep(200);
    }
    throw new Error(`lock ${this.cfg.ip}:80 unreachable (never woke)`);
  }

  private async ensureToken(): Promise<void> {
    if (this.token) return;
    const body = { method: 'login', params: {
      appType: 'Tapo_Android', cloudUserName: this.cfg.cloudUsername,
      cloudPassword: this.cfg.cloudPassword, terminalUUID: this.cfg.terminalUUID,
      refreshTokenNeeded: false } };
    const r = await (await fetch('https://wap.tplinkcloud.com/', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    })).json() as Json;
    if (r.error_code !== 0) throw new Error(`login failed: ${JSON.stringify(r)}`);
    this.token = r.result.token;
    this.accountId = this.accountId ?? String(r.result.accountId);
  }

  // handshake0 -> cloud control-key -> handshake1/2 -> derive session keys
  private async handshake(): Promise<Session> {
    const base = `http://${this.cfg.ip}:80`;
    const localHeaders = { 'Content-Type': 'text/plain', 'Referer': `${base}/` };

    // handshake0 (33-byte body = sha((rand4hex+accountId).upper()) + ROLE=0)
    const rand4 = crypto.randomBytes(4);
    const digest = sha(Buffer.from((rand4.toString('hex') + this.accountId).toUpperCase(), 'ascii'));
    const hs0 = await fetch(`${base}/app/handshake0`, {
      method: 'POST', headers: localHeaders,
      body: new Uint8Array(Buffer.concat([digest.subarray(0, 32), Buffer.from([0])])),
    });
    if (!hs0.ok) throw new Error(`handshake0 HTTP ${hs0.status}`);
    const secret = (await hs0.text()).trim();

    // cloud control-key (bound to THIS handshake0).
    // TP-Link's app-server uses a private CA ("self-signed" to public roots), so
    // this single call skips TLS verification via node:https. The login call
    // above (which carries the account password) stays fully verified.
    const ckRes = await httpsPostJson(
      `https://use1-app-server.iot.i.tplinknbu.com/v1/things/${this.cfg.deviceId}/control-key`,
      {
        'Authorization': `ut|${this.token}`,
        'app-cid': `app:Tapo_Android:${this.cfg.terminalUUID}`,
        'App-Type': 'Tapo_Android', 'x-app-name': 'Tapo_Android',
        'UUID': this.cfg.terminalUUID, 'Terminal-Id': this.cfg.terminalUUID, 'x-term-id': this.cfg.terminalUUID,
        'Platform': 'ANDROID', 'X-App-Os': 'android', 'Content-Type': 'application/json',
      },
      { secret, random: rand4.toString('hex').toUpperCase() },
      false,   // TP-Link private CA -> can't verify against public roots
    ) as Json;
    const ckObj = ckRes.result ?? ckRes.data ?? ckRes;
    const controlKey: string | undefined = ckObj.controlKey ?? ckObj.control_key;
    if (!controlKey) throw new Error(`control-key missing: ${JSON.stringify(ckRes)}`);

    // handshake1 (verify server) + capture TP_SESSIONID cookie
    const ck = Buffer.from(controlKey.toUpperCase(), 'ascii');   // 64 ASCII bytes, owner raw
    const lmk = sha(ck);
    const L = crypto.randomBytes(16);
    const hs1 = await fetch(`${base}/app/handshake1`, {
      method: 'POST', headers: localHeaders,
      body: new Uint8Array(Buffer.concat([L, sha(Buffer.concat([L, ck]))])),
    });
    if (!hs1.ok) throw new Error(`handshake1 HTTP ${hs1.status}`);
    const m = /TP_SESSIONID=[^;]+/.exec(hs1.headers.get('set-cookie') ?? '');
    if (!m) throw new Error('no TP_SESSIONID cookie on handshake1');
    const cookie = m[0];
    const hs1Body = Buffer.from(await hs1.arrayBuffer());
    const R = hs1Body.subarray(0, 16);
    const serverProof = hs1Body.subarray(16, 48);
    if (!sha(Buffer.concat([L, R, lmk])).equals(serverProof)) {
      throw new Error('handshake1 server proof mismatch (bad control key / stale hs0?)');
    }

    // handshake2
    const hs2 = await fetch(`${base}/app/handshake2`, {
      method: 'POST', headers: { ...localHeaders, 'Cookie': cookie },
      body: new Uint8Array(sha(Buffer.concat([R, L, lmk]))),
    });
    if (!hs2.ok) throw new Error(`handshake2 HTTP ${hs2.status}`);

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
