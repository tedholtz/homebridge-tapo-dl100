# homebridge-tapo-dl100

A [Homebridge](https://homebridge.io) plugin that adds **HomeKit lock control** for the **TP-Link Tapo DL100** Smart Wi-Fi Door Lock.

[![npm](https://img.shields.io/npm/v/homebridge-tapo-dl100)](https://www.npmjs.com/package/homebridge-tapo-dl100)
[![Homebridge](https://img.shields.io/badge/homebridge-%3E%3D1.6.0-blueviolet)](https://homebridge.io)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Background

The DL100 uses a proprietary local transport called **DLKLAP** — a variant of TP-Link's KLAP protocol with a unique three-way handshake, cloud-bound control key, and AES-128-CBC session encryption over plain HTTP on port 80. At the time this plugin was written, no open-source HomeKit, Home Assistant, or python-kasa integration supported the DL100 or the DLKLAP protocol.

This plugin is the result of a full reverse-engineering effort: BLE captures, APK decompilation, and live MITM packet analysis. The DLKLAP protocol is fully solved and device-verified (lock & unlock, end-to-end, 2026-07-02).

> **Protocol spec:** See [`PROTOCOL.md`](PROTOCOL.md) for the full DLKLAP reverse-engineering notes, wire format, and session key derivation — useful if you want to port this to python-kasa, Home Assistant, or another platform.

---

## Features

- 🔒 **Lock / Unlock** from HomeKit, Siri, and Shortcuts
- 🔋 **Battery level** and low-battery alerts in HomeKit
- ⚡ **Local control** — commands go directly to the lock over your LAN; cloud is only contacted once per session to mint a session key
- 🔄 **Auto-relock detection** — polls every 5 s after an unlock to catch the auto-relock quickly
- 💾 **Session caching** — skips the cloud round-trip on back-to-back operations (~2.5 s unlock latency)
- 🔌 **Dynamic platform** — supports multiple DL100 locks on the same Homebridge instance

---

## Requirements

- **Homebridge** ≥ 1.6.0
- **Node.js** ≥ 18
- A **TP-Link / Tapo account** that owns the lock (the same account used in the Tapo app)
- The lock and Homebridge host must be on the **same LAN**
- Outbound internet access from the Homebridge host (for the cloud login and session key)

---

## Installation

### Via Homebridge UI (recommended)

Search for `homebridge-tapo-dl100` in the Homebridge plugin tab and click **Install**.

### Manual (on the Homebridge host)

```bash
npm install -g homebridge-tapo-dl100
```

Then restart Homebridge.

---

## Configuration

Add a `TapoDL100` platform block to your Homebridge `config.json`:

```json
{
  "platforms": [
    {
      "platform": "TapoDL100",
      "locks": [
        {
          "name": "Front Door",
          "ip": "192.168.1.100",
          "cloudUsername": "you@example.com",
          "cloudPassword": "your-tapo-password",
          "pollSeconds": 300
        }
      ]
    }
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `name` | ✅ | Friendly name — must match the device name in the Tapo app exactly if you have multiple DL100s |
| `ip` | ✅ | Local IP address of the lock |
| `cloudUsername` | ✅ | TP-Link / Tapo account email (the account that **owns** the lock) |
| `cloudPassword` | ✅ | TP-Link / Tapo account password |
| `pollSeconds` | — | How often to poll the lock for state changes (default: `300`). Each poll wakes the radio — increase if battery drains faster than expected |

`deviceId` and `terminalUUID` are resolved automatically on first connect and cached by Homebridge; you never need to supply them.

> **Tip:** Find your lock's IP in your router's DHCP table, or in the Tapo app under Device Info. Assign it a static DHCP lease so the IP doesn't change.

---

## How it Works

The DL100 uses **DLKLAP over plain HTTP on port 80**. Each session involves:

1. **Cloud login** — exchanges your Tapo credentials for a session token
2. **Handshake 0** — sends a 33-byte binary challenge to the lock
3. **Cloud control key** — the cloud mints a 64-char AES key bound to that specific handshake
4. **Handshake 1 / 2** — mutual authentication; the lock sets a `TP_SESSIONID` cookie
5. **Session key derivation** — `lsk` (AES key), `ldk` (MAC key), `ivb` + `seq` (IV)
6. **Encrypted requests** — AES-128-CBC + HMAC-SHA256, incrementing sequence number, over `/app/request`

After session establishment, all lock/unlock commands and status reads are **fully local** — no cloud involved per-command.

See [`PROTOCOL.md`](PROTOCOL.md) for the full wire-level specification.

---

## Lock Status Mapping

| DL100 `lock_status` | Meaning | HomeKit Current State | HomeKit Target State |
|---|---|---|---|
| `0` | Bolt extended — **LOCKED** | SECURED (1) | SECURED (1) |
| `1` | Bolt retracted — **UNLOCKED** | UNSECURED (0) | UNSECURED (0) |
| `2` | Uninitialized | UNKNOWN (3) | — |
| `3` | Jammed (unlocking) | JAMMED (2) | — |
| `4` | Jammed (locking) | JAMMED (2) | — |

---

## Troubleshooting

**`15033` / "app account confirm not match"**
The account in the plugin config must be the **owner** account registered in the Tapo app — not a shared-user account. Verify `cloudUsername`/`cloudPassword` exactly match the account that added the lock.

**`SELF_SIGNED_CERT_IN_CHAIN`**
TP-Link's control-key server (`use1-app-server.iot.i.tplinknbu.com`) uses a private CA. The plugin handles this automatically by using Node's `node:http`/`node:https` directly for that one call.

**Don't use `fetch` / undici in forks**
Undici mangles the 33-byte binary handshake body, causing the cloud to reject the session with `15033`. All requests in this plugin use Node's built-in `node:http`/`node:https` — keep it that way.

**`EADDRINUSE`**
A stale child-bridge process is holding the HAP port. Run `sudo systemctl restart homebridge` to clear it.

**"Accessory Already in Another Home" after a hub outage**
Remove the `_bridge` block from the `TapoDL100` platform entry in `/var/lib/homebridge/config.json` and restart Homebridge. The lock will appear under the main bridge — no re-pairing needed.

**Lock not reachable / connection timeout**
The DL100 radio sleeps between operations. The plugin connects directly to port 80 and the lock wakes within ~1.1 s. If connections time out consistently, check that the Homebridge host and lock are on the same subnet and that your router isn't blocking intra-LAN traffic.

---

## Contributing

Pull requests welcome! A few areas where contributions would be especially valuable:

- **python-kasa / Home Assistant port** — the DLKLAP transport needs a `DlklapTransport` class in python-kasa ([issue #1693](https://github.com/python-kasa/python-kasa/issues/1693))
- **Lighter status reads** — try `getLockStatus` instead of `getDeviceInfo` to reduce radio wake frequency
- **Concurrency guard** — a per-lock mutex to handle simultaneous sessions from the plugin and the Tapo app
- **TP-Link CA pinning** — replace the `rejectUnauthorized: false` on the control-key call with a pinned TP-Link CA cert

---

## License

MIT © Ted Holtz
