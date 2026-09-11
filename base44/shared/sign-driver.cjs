'use strict';
// Driver: runs IronFingerprint.nativeSign from libiron_fingerprint.so inside the
// ARM64 emulator and returns the X-Iron-* header set for a given /api/ request path.
const fs = require('fs');
const path = require('path');
const { createEmu } = require('./iron-emu.cjs');

const ROOT = path.resolve(__dirname, '..', '..');
const SO = (() => {
  const b64 = fs.readFileSync(path.join(ROOT, 'iron_so.b64'), 'utf8');
  return Buffer.from(b64.replace(/\s+/g, ''), 'base64');
})();
const APK = fs.readFileSync(path.join(ROOT, 'OscarTV.apk'));

const CODE_PATH = '/data/app/~~xyz/com.drama.mp4-AbCdEf/base.apk';
const FAKE_MAPS = [
  '12c00000-12c98000 r--p 00000000 103:02 1234   ' + CODE_PATH,
  '7fc12a0000-7fc12c4000 r-xp 00000000 103:02 5678  /data/app/~~xyz/com.drama.mp4-AbCdEf/lib/arm64/libiron_fingerprint.so',
  '7fc12c4000-7fc12c7000 r--p 00000000 103:02 5678  /data/app/~~xyz/com.drama.mp4-AbCdEf/lib/arm64/libiron_fingerprint.so',
].join('\n');

const NATIVE_SIGN = 0x1e530;
const PKG = 'com.drama.mp4';

function randHex8() {
  let s = '';
  for (let i = 0; i < 8; i++) s += '0123456789abcdef'[Math.floor(Math.random() * 16)];
  return s;
}

// p is the exact string the app passes to nativeSign (the request path).
// opts.ts / opts.nonce override the generated values (for header testing).
function signPath(p, opts = {}) {
  const ts = opts.ts != null ? String(opts.ts) : Math.floor(Date.now() / 1000).toString();
  const nonce = opts.nonce != null ? String(opts.nonce) : randHex8();
  globalThis.__jniCalls = [];
  globalThis.__libcCalls = [];
  globalThis.__fmtCalls = [];
  const emu = createEmu(SO, {
    jstrings: [PKG, p, ts, nonce],
    packageName: PKG,
    codePath: CODE_PATH,
    files: {
      '/proc/self/maps': FAKE_MAPS,
      '/proc/self/status': 'Name:\tcom.drama.mp4\nTracerPid:\t0\n',
    },
    filesBinary: { [CODE_PATH]: APK },
    maxSteps: opts.maxSteps || 300_000_000,
    collectStrings: !!opts.collectStrings,
    logCalls: !!opts.logCalls,
    trace: opts.trace || null,
  });
  // 0x4bcd8 = "environment verified" flag normally set to 1 by the library's init path
  // (JNI_OnLoad-era verification of the .so/APK). We invoke nativeSign directly, so we
  // pre-seed it to simulate a genuine, already-initialized device.
  emu.buf[0x4bcd8] = 1;
  let result = null, err = null;
  try {
    result = emu.run(NATIVE_SIGN, [0x2000000, 0x2000, 0x2100, 0x3000, 0x3001, 0x3002, 0x3003]);
  } catch (e) {
    err = (e && e.message) || String(e);
  }
  const sig = result ? result.result : null;
  return {
    ok: !err && typeof sig === 'string' && sig.length > 0,
    sig,
    err,
    steps: result ? result.steps : 0,
    ts,
    nonce,
    headers: typeof sig === 'string' && sig.length > 0
      ? { 'X-Iron-Sig': sig, 'X-Iron-Ts': ts, 'X-Iron-Nonce': nonce }
      : null,
    fmtCalls: (globalThis.__fmtCalls || []).slice(0, 10),
    allStrings: globalThis.__newStrings || [],
    jniResolved: (globalThis.__jniCalls || []).filter((c) => c.resolved).map((c) => c.resolved + '=' + c.value),
  };
}

module.exports = { signPath };