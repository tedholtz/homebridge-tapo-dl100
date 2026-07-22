# DLKLAP Protocol Specification — TP-Link Tapo DL100

This document describes the **DLKLAP** transport protocol used by the TP-Link Tapo DL100 Smart Wi-Fi Door Lock. It is the result of a complete reverse-engineering effort involving BLE packet capture, Android APK decompilation, and live MITM session analysis.

**Status:** Fully solved and device-verified (lock & unlock, end-to-end) as of 2026-07-02.

> This spec is intended to enable ports to other platforms (python-kasa, Home Assistant, etc.). See [python-kasa issue #1693](https://github.com/python-kasa/python-kasa/issues/1693) for the current porting effort.

---

## Table of Contents

1. [Device Facts](#1-device-facts)
2. [Protocol Overview](#2-protocol-overview)
3. [Notation](#3-notation)
4. [Step-by-Step Session](#4-step-by-step-session)
   - [4.1 Cloud Login](#41-cloud-login)
   - [4.2 Handshake 0 (local)](#42-handshake-0-local)
   - [4.3 Cloud Control Key](#43-cloud-control-key)
   - [4.4 Handshake 1 (local — server auth)](#44-handshake-1-local--server-auth)
   - [4.5 Handshake 2 (local — client auth)](#45-handshake-2-local--client-auth)
   - [4.6 Session Key Derivation](#46-session-key-derivation)
   - [4.7 Encrypted Requests](#47-encrypted-requests)
5. [Device Commands](#5-device-commands)
   - [5.1 Get Device Info](#51-get-device-info)
   - [5.2 Lock / Unlock](#52-lock--unlock)
6. [Lock Status Encoding](#6-lock-status-encoding)
7. [Required HTTP Headers](#7-required-http-headers)
8. [Error Codes](#8-error-codes)
9. [Wi-Fi Reachability / Radio Wake](#9-wi-fi-reachability--radio-wake)
10. [Session Management Notes](#10-session-management-notes)
11. [TLS Notes](#11-tls-notes)
12. [Reverse Engineering Sources](#12-reverse-engineering-sources)

---

## 1. Device Facts

| Field | Value |
|---|---|
| Model | DL100 (`SMART.TAPOLOCK`) |
| Encryption scheme | `DLKLAP` |
| Transport | Plain HTTP, port 80 (`is_support_https=False`) |
| Login version | `2` |
| Firmware (tested) | `1.0.17 Build 260417 Rel.082002` |
| Device family | `SMART.TAPOLOCK` |

The DL100 shares the `SMART.TAPOLOCK` device family string with the DL110, but uses an entirely different transport. The DL110 uses HTTPS + AES (same as Tapo cameras); the DL100 uses DLKLAP over plain HTTP. They are not interchangeable.

---

## 2. Protocol Overview

DLKLAP is a TP-Link proprietary protocol layered over plain HTTP. A session requires:

1. A **cloud login** to obtain a bearer token.
2. A **local Handshake 0** that sends a challenge to the lock and receives a `secret`.
3. A **cloud control-key** request that binds a 64-char AES key to that specific Handshake 0.
4. A **local Handshake 1 / 2** mutual authentication that derives a `TP_SESSIONID` cookie.
5. **Session key derivation** (KDF over SHA-256) producing encryption and MAC keys.
6. **Encrypted `multipleRequest` calls** over `/app/request` for all device operations.

After step 5, all traffic is local. The cloud is not involved in individual lock/unlock commands.

**One handshake 0 per session.** Sending a second Handshake 0 rotates device state and immediately invalidates the first session's control key (the cloud returns error `15033`).

---

## 3. Notation

- `sha(x)` = SHA-256 digest of byte string `x`; returns 32 bytes.
- `sha(a, b, ...)` = SHA-256 of the concatenation of all arguments.
- `AES-CBC(key, iv, data)` = AES-128-CBC encrypt/decrypt with PKCS#7 padding.
- `||` = byte concatenation.
- `rand4` = 4 random bytes generated fresh per session.
- `ck` = the 64-character UPPERCASE ASCII hex `controlKey`, used **raw as ASCII bytes** — never decoded with `bytes.fromhex()`.
- All hex strings produced by the client (e.g. `rand4.hex().upper()`) are uppercase ASCII.

---

## 4. Step-by-Step Session

### 4.1 Cloud Login

```
POST https://wap.tplinkcloud.com/
Content-Type: application/json

{
  "method": "login",
  "params": {
    "appType": "Tapo_Android",
    "cloudUserName": "<email>",
    "cloudPassword": "<password>",
    "terminalUUID": "<UUID>",
    "refreshTokenNeeded": false
  }
}
```

Response:
```json
{
  "error_code": 0,
  "result": {
    "token": "<token>",
    "accountId": "<accountId>"
  }
}
```

- Generate `terminalUUID` once (any UUID v4 works) and reuse it for the entire session and all subsequent requests.
- Save `token` and `accountId`.

---

### 4.2 Handshake 0 (local)

```
POST http://<lock-ip>:80/app/handshake0
Content-Type: text/plain
Referer: http://<lock-ip>:80/

<33-byte binary body>
```

**Body construction:**

```python
rand4 = os.urandom(4)
digest = sha(((rand4.hex() + accountId).upper()).encode('ascii'))  # lowercase hex, then upper the whole string
body = digest[:32] + bytes([0])  # 32-byte digest + 1-byte role (0 = owner)
```

> **Critical:** The hash input is `(hex(rand4) + accountId)` uppercased as a single string — not `hex(rand4).upper() + accountId.upper()`. Case matters.

Response: a 236-character base64 string — the `secret`. Pass it verbatim to the cloud control-key step.

---

### 4.3 Cloud Control Key

```
POST https://use1-app-server.iot.i.tplinknbu.com/v1/things/<deviceId>/control-key
Authorization: ut|<token>
app-cid: app:Tapo_Android:<UUID>
App-Type: Tapo_Android
x-app-name: Tapo_Android
UUID: <UUID>
Terminal-Id: <UUID>
x-term-id: <UUID>
Platform: ANDROID
X-App-Os: android
Content-Type: application/json

{
  "secret": "<hs0 base64 response>",
  "random": "<rand4.hex().upper()>"
}
```

> **Note:** `rand4` appears lowercase-hex inside the Handshake 0 hash, but **uppercase-hex** in the `random` field here.

Response:
```json
{
  "result": {
    "controlKey": "<64-char uppercase hex string>",
    "accessInfo": "<base64>"
  }
}
```

- `controlKey` is the session AES key used **raw as 64 ASCII bytes** (do not decode it as hex).
- `accessInfo` is a shared-user token; owners discard it.
- Each call re-mints a key bound to that specific Handshake 0. Do not call this twice for the same hs0.

> **TLS note:** This host presents a TP-Link private CA certificate not trusted by public roots. Disable TLS verification for this single call only. See [§11 TLS Notes](#11-tls-notes).

---

### 4.4 Handshake 1 (local — server auth)

```
POST http://<lock-ip>:80/app/handshake1
Content-Type: text/plain
Referer: http://<lock-ip>:80/

<48-byte binary body>
```

**Body construction:**

```python
ck  = controlKey.upper().encode('ascii')   # 64 ASCII bytes
lmk = sha(ck)                              # 32 bytes
L   = os.urandom(16)                       # local seed
body = L + sha(L + ck)                     # 16 + 32 = 48 bytes
```

Response: 48 bytes
- Bytes `[0:16]` = remote seed `R`
- Bytes `[16:48]` = `server_proof`

**Verify server:**
```python
assert sha(L + R + lmk) == server_proof
```

**Capture the session cookie** from the `Set-Cookie` response header:
```
Set-Cookie: TP_SESSIONID=<value>; ...
```

Echo `Cookie: TP_SESSIONID=<value>` on Handshake 2 and every subsequent `/app/request`.

---

### 4.5 Handshake 2 (local — client auth)

```
POST http://<lock-ip>:80/app/handshake2
Content-Type: text/plain
Referer: http://<lock-ip>:80/
Cookie: TP_SESSIONID=<value>

<32-byte binary body>
```

**Body:**
```python
body = sha(R + L + lmk)   # 32 bytes
```

Expected response: HTTP 200. No body is used.

---

### 4.6 Session Key Derivation

```python
def kdf(tag: str) -> bytes:
    return sha(tag.encode('ascii') + L + R + lmk)

lsk  = kdf('lsk')[:16]          # AES-128 encryption key
ldk  = kdf('ldk')[:28]          # HMAC key (28 bytes)
ivb  = kdf('iv')[:12]           # base IV (12 bytes)
seq0 = int.from_bytes(kdf('iv')[28:32], 'big') & 0x7FFFFFFF   # initial sequence number
```

---

### 4.7 Encrypted Requests

All device commands use:

```
POST http://<lock-ip>:80/app/request?seq=<seq>
Content-Type: text/plain
Referer: http://<lock-ip>:80/
Accept: application/json
requestByApp: true
Cookie: TP_SESSIONID=<value>

<binary: mac || ciphertext>
```

**Encrypt:**
```python
seq   = seq0 + 1                        # increment by 1 per request
seq_b = seq.to_bytes(4, 'big')
iv    = ivb + seq_b                     # 12 + 4 = 16 bytes (full CBC IV)
ct    = AES-CBC-encrypt(key=lsk, iv=iv, PKCS7(plaintext_json_bytes))
mac   = sha(ldk + seq_b + ct)           # seq4 KLAP MAC form
body  = mac + ct                        # 32 + len(ct) bytes
```

**Decrypt response:**
```python
# response body = mac(32 bytes) || ciphertext
dec = AES-CBC-decrypt(key=lsk, iv=iv, response_body[32:])
dec = PKCS7-unpad(dec)
# There is a ~4-byte prefix before the JSON; parse from the first '{'
json_str = dec[dec.index(b'{'):]
result = json.loads(json_str)
```

**Plaintext envelope** (standard Tapo `multipleRequest` passthrough):
```json
{
  "method": "multipleRequest",
  "params": {
    "requests": [
      { "method": "<command>", "params": { ... } }
    ]
  }
}
```

---

## 5. Device Commands

### 5.1 Get Device Info

```json
{ "method": "getDeviceInfo" }
```

Example response excerpt (after decryption and `multipleRequest` unwrap):
```json
{
  "type": "SMART.TAPOLOCK",
  "model": "DL100",
  "lock_status": 0,
  "battery_percentage": 100,
  "at_low_battery": false,
  "rssi": -37,
  "nickname": "RnJvbnQgRG9vcg==",
  "ssid": "<base64>",
  "region": "America/New_York",
  "time_diff": -300
}
```

- `nickname` and `ssid` are base64-encoded strings.
- `lock_status` encoding: see [§6](#6-lock-status-encoding).

---

### 5.2 Lock / Unlock

**Method:** `setLockStatus`

```json
{
  "method": "setLockStatus",
  "params": {
    "lock_status": 0,
    "sa_user_id": "local_1"
  }
}
```

| Field | Owner value | Notes |
|---|---|---|
| `lock_status` | `0` to lock, `1` to unlock | See [§6](#6-lock-status-encoding) |
| `sa_user_id` | `"local_1"` | Owner always sends `"local_1"` |
| `tplink_account` | omit | Include only for shared users (`sa_user_id` starts with `"share_"`) |
| `access_info` | omit | Include only if `setLockStatus` returns an error and you have an `accessInfo` from the control-key response |
| `lock_type` / `unlock_type` | omit | Send `null` (omit) for a plain app lock/unlock |

Expected response:
```json
{ "error_code": 0, "result": { "responses": [{ "error_code": 0, "result": { "status": 0 } }] } }
```

---

## 6. Lock Status Encoding

The `lock_status` field in both `getDeviceInfo` (read) and `setLockStatus` (write) uses the same `EnumDoorLockStatus` encoding:

| `lock_status` value | Physical state | HomeKit `LockCurrentState` |
|---|---|---|
| `0` | Bolt **extended** — **LOCKED** | SECURED (1) |
| `1` | Bolt **retracted** — **UNLOCKED** | UNSECURED (0) |
| `2` | UNINITIALIZED | UNKNOWN (3) |
| `3` | JAM_IN_UNLOCKING | JAMMED (2) |
| `4` | JAM_IN_LOCKING | JAMMED (2) |

> **Counter-intuitive:** `0 = OFF = locked` and `1 = ON = unlocked`. The `DoorLockLockStatus` raw-string enum (`"0"`/`"1"`) found in decompiled sources is a red herring — it is **not** what `setLockStatus` sends.

**Commands:** `setLockStatus` uses the same encoding: send `0` to lock, `1` to unlock.

---

## 7. Required HTTP Headers

### Local requests (Handshake 0, 1, 2, and `/app/request`)

```
Content-Type: text/plain
Referer: http://<lock-ip>:80/
```

Additionally for `/app/request`:
```
Accept: application/json
requestByApp: true
Cookie: TP_SESSIONID=<value>
```

### Cloud control-key request

```
Authorization: ut|<token>
app-cid: app:Tapo_Android:<UUID>
App-Type: Tapo_Android
x-app-name: Tapo_Android
UUID: <UUID>
Terminal-Id: <UUID>
x-term-id: <UUID>
Platform: ANDROID
X-App-Os: android
Content-Type: application/json
```

---

## 8. Error Codes

| Code | Where | Meaning | Fix |
|---|---|---|---|
| `15051` | Cloud control-key | Decrypt fail — `secret` bytes wrong | Verify Handshake 0 body construction; check `accountId` |
| `15033` | Cloud control-key | Account confirm mismatch | `random`/`accountId` don't match hs0 hash, or a second hs0 was sent (rotates device state) |
| `403` (hs1/hs2) | Local | Missing or stale cookie, or second hs0 | Never send more than one hs0 per session; echo the cookie |
| `403` (/app/request) | Local | MAC or seq rejected | Verify MAC form is `sha(ldk + seq4 + ct)`, seq starts at `seq0 + 1` |

---

## 9. Wi-Fi Reachability / Radio Wake

The DL100 Wi-Fi radio enters power-save mode between operations. Port 80 may appear `filtered` to fast scanners (e.g. nmap with a single probe), but the radio is not firewalled — it simply takes a moment to wake.

**Wake behavior (verified):**
- A TCP `connect()` to port 80 wakes the radio. The lock responds to Handshake 0 within ~1.1 s cold.
- No explicit wake probe is needed — simply begin Handshake 0 and retry on `ECONNREFUSED` with a short backoff.
- A physical keypad press does not change the scan result; it is not needed to wake the radio for software access.

---

## 10. Session Management Notes

- **One hs0 per session.** A second Handshake 0 rotates the device's internal state and invalidates the first session's cloud control key (`15033`).
- **Serialize session establishment.** If two operations race to establish a session, serialize them — only one should run hs0 at a time.
- **Reuse the session.** After establishment, reuse `lsk`/`ldk`/`ivb`/`seq`/cookie across operations. Only re-handshake on failure.
- **Increment `seq` per request.** The sequence number in the URL query (`?seq=<n>`) and in the MAC (`sha(ldk + seq_b + ct)`) must match and increase monotonically within a session.
- **Cloud token lifetime.** The login token can be cached across restarts and refreshed on failure.

---

## 11. TLS Notes

- **Cloud login** (`wap.tplinkcloud.com`): standard TLS, fully verifiable against public roots. Always verify.
- **Cloud control-key** (`use1-app-server.iot.i.tplinknbu.com`): uses a TP-Link private CA not trusted by public roots. TLS verification must be disabled for this single call. The account password is **not** sent to this endpoint (only the session token), so the risk is limited. Future hardening: pin TP-Link's CA certificate and re-enable verification.
- **Local lock** (`http://<ip>:80`): plain HTTP, no TLS.

---

## 12. Reverse Engineering Sources

This specification was derived from:

- **Live MITM capture** (`tapo_dl100.mitm`) — Wi-Fi traffic between the Tapo Android app and the DL100 on a local network with a transparent HTTPS proxy.
- **Android APK decompilation** — decompiled sources including:
  - `DoorLockRepository.java` — owner raw-key derivation (`K()`/`H()`), `C3()` (setLockStatus builder)
  - `ThingControlKeyResult.java` — `controlKey`/`accessInfo` fields
  - `DoorLockStatusParams.java` — `@SerializedName` field names
  - `DoorLockKLAPTransport` — transport-layer framing
  - `DoorLockSAUtils.f()` — `sa_user_id` logic (`"local_1"` for owner)
  - `DoorLockLocalControlKeyUtils` — local key handling
  - `j70/a.java` (interceptor) — header injection
- **BLE captures** (`FrontDoor.pklg`, `LockAndUnlock.pklg`) — confirmed BLE is only used during initial device setup; routine lock/unlock is Wi-Fi-only.
- **Device-verified testing** (`step9.py`) — Python script confirming end-to-end session establishment and bidirectional lock/unlock against a live DL100.
