'use strict';
// Runs nativeCertDiag (and nativeSign) from libiron_fingerprint.so inside the
// ARM64 emulator — used to derive the X-Iron-Diag header value for OscarTV.
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
const PKG = 'com.drama.mp4';

// parse .dynsym exports
function dynsyms() {
  const e_shoff = Number(SO.readBigUInt64LE(40));
  const e_shentsize = SO.readUInt16LE(58), e_shnum = SO.readUInt16LE(60), e_shstrndx = SO.readUInt16LE(62);
  const shOff = (i) => Number(SO.readBigUInt64LE(e_shoff + i * e_shentsize + 24));
  const shSize = (i) => Number(SO.readBigUInt64LE(e_shoff + i * e_shentsize + 32));
  const shName = (i) => SO.readUInt32LE(e_shoff + i * e_shentsize);
  let shstr = null;
  for (let i = 0; i < e_shnum; i++) if (i === e_shstrndx) shstr = SO.slice(shOff(i), shOff(i) + shSize(i));
  const secName = (i) => { const o = shName(i); const e = shstr.indexOf(0, o); return shstr.slice(o, e).toString(); };
  let dynsym = -1, dynstr = -1;
  for (let i = 0; i < e_shnum; i++) { const n = secName(i); if (n === '.dynsym') dynsym = i; if (n === '.dynstr') dynstr = i; }
  const strtab = SO.slice(shOff(dynstr), shOff(dynstr) + shSize(dynstr));
  const out = [];
  const count = Math.floor(shSize(dynsym) / 24);
  for (let i = 0; i < count; i++) {
    const base = shOff(dynsym) + i * 24;
    const no = SO.readUInt32LE(base);
    const val = Number(SO.readBigUInt64LE(base + 8));
    if (!val) continue;
    const e = strtab.indexOf(0, no);
    out.push({ name: strtab.slice(no, e).toString(), addr: val });
  }
  return out;
}

function makeEmu(jstrings, logCalls) {
  return createEmu(SO, {
    jstrings,
    packageName: PKG,
    codePath: CODE_PATH,
    files: {
      '/proc/self/maps': FAKE_MAPS,
      '/proc/self/status': 'Name:\tcom.drama.mp4\nTracerPid:\t0\n',
    },
    filesBinary: { [CODE_PATH]: APK },
    maxSteps: 300_000_000,
    logCalls: !!logCalls,
  });
}

// static scan: list SIMD instructions the current handlers can't run (or run wrongly)
function scanRange(buf, start, end) {
  const problems = {};
  const add = (key, a, i) => {
    if (!problems[key]) problems[key] = { count: 0, first: [] };
    const p = problems[key];
    p.count++;
    if (p.first.length < 4) p.first.push('0x' + a.toString(16) + ':0x' + i.toString(16));
  };
  for (let a = start; a < end; a += 4) {
    const i = buf.readUInt32LE(a);
    const pre = (i >>> 24) & 0x0f;
    if (pre !== 0x0e && pre !== 0x0f) continue;
    const b21 = (i >>> 21) & 1, b10 = (i >>> 10) & 1;
    const u = (i >>> 29) & 1, q = (i >>> 30) & 1, sz = (i >>> 22) & 3;
    if (pre === 0x0e && b21 === 1 && b10 === 1) {
      const op = (i >> 11) & 31;
      if (![3, 6, 7, 8, 9, 10, 11, 16, 19].includes(op)) add('3same op=' + op + ' u=' + u + ' sz=' + sz, a, i);
      if (op === 19 && u) add('PMUL (MUL slot U=1)', a, i);
    } else if (pre === 0x0e && b21 === 0 && b10 === 1) {
      const op = (i >> 11) & 31;
      const ok = (op === 1 && !u) || (op === 0 && !u && !q) || (op === 3 && !u && q) || ((op === 5 || op === 7) && u);
      if (!ok) add('copy op=' + op + ' u=' + u + ' q=' + q, a, i);
    } else if (pre === 0x0f) {
      // by-element family — none implemented. Skip the shift-by-immediate shapes
      // already handled (immh!=0 with our known shift opcodes, or MOVI immh==0).
      const immh = (i >>> 19) & 0xf;
      const opBig = (i >> 11) & 0x1f;
      const isShift = immh !== 0 && [0, 2, 8, 10, 20].includes(opBig);
      const isMovi = immh === 0 && q !== undefined; // handled by MOVI path
      if (!isShift && !isMovi) add('byelem op15_12=' + ((i >> 12) & 15) + ' sz=' + sz + ' u=' + u + ' L=' + ((i >>> 21) & 1), a, i);
    } else if (pre === 0x0e && b21 === 1 && b10 === 0 && ((i >>> 17) & 15) === 0 && ((i >>> 11) & 1) === 1) {
      add('2rmisc op=' + ((i >> 12) & 31), a, i); // two-reg-misc — not implemented
    }
  }
  return problems;
}

function runAt(entry, args, jstrings, logCalls) {
  globalThis.__jniCalls = [];
  globalThis.__fmtCalls = [];
  globalThis.__libcCalls = [];
  const emu = makeEmu(jstrings, logCalls);
  emu.buf[0x4bcd8] = 1;
  try {
    const r = emu.run(entry, args);
    return {
      ok: r.result != null || true,
      result: r.result,
      steps: r.steps,
      fmt: (globalThis.__fmtCalls || []).slice(0, 8),
      jni: (globalThis.__jniCalls || []).filter((c) => c.resolved).map((c) => c.resolved + '=' + c.value).slice(0, 25),
      stubs: (globalThis.__jniCalls || []).filter((c) => c.slot).slice(-15),
      libc: (globalThis.__libcCalls || []).slice(-40),
    };
  } catch (e) {
    return {
      ok: false,
      err: e.message,
      fmt: (globalThis.__fmtCalls || []).slice(0, 8),
      jni: (globalThis.__jniCalls || []).filter((c) => c.resolved).map((c) => c.resolved + '=' + c.value).slice(0, 25),
      stubs: (globalThis.__jniCalls || []).filter((c) => c.slot).slice(-15),
      libc: (globalThis.__libcCalls || []).slice(-40),
    };
  }
}

module.exports = { dynsyms, makeEmu, scanRange, runAt, PKG };