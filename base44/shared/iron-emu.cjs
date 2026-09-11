'use strict';
// ARM64 emulator for libiron_fingerprint.so nativeSign — analysis tooling
const fs = require('fs');

function createEmu(SO, opts = {}) {
  opts.logUnknown = true;
  const MEMSZ = 0x4000000; // 64MB
  const buf = Buffer.alloc(MEMSZ);
  const rd64 = (o) => buf.readBigUInt64LE(Number(o));
  const wr64 = (o, v) => {
    const masked = BigInt(v) & 0xffffffffffffffffn;
    if (opts.traceVal !== undefined && masked === BigInt(opts.traceVal)) globalThis.__wlog.push('wr64 0x' + Number(o).toString(16) + ' at pc=0x' + pc.toString(16));
    buf.writeBigUInt64LE(masked, Number(o));
  };
  const rd32 = (o) => buf.readUInt32LE(Number(o));
  const wr32 = (o, v) => { buf.writeUInt32LE(Number(v) >>> 0, Number(o)); };

  // ---- map segments ----
  const e_phoff = SO.readUInt32LE(32), e_phentsize = SO.readUInt16LE(54), e_phnum = SO.readUInt16LE(56);
  const segs = [];
  for (let i = 0; i < e_phnum; i++) {
    const o = e_phoff + i * e_phentsize;
    const type = SO.readUInt32LE(o);
    if (type === 1) {
      const off = Number(SO.readBigUInt64LE(o + 8));
      const vaddr = Number(SO.readBigUInt64LE(o + 16));
      const filesz = Number(SO.readBigUInt64LE(o + 32));
      const memsz = Number(SO.readBigUInt64LE(o + 40));
      segs.push({ off, vaddr, filesz, memsz });
      SO.copy(buf, vaddr, off, off + filesz);
    }
  }
  const STACK_TOP = 0x800000n;
  const HEAP = 0x1000000n;
  let heapPtr = HEAP;
  const ENV = 0x2000000n;
  const JNITABLE = 0x2001000n;
  const MAGIC_F = 0xB0000000n;
  const MAGIC_LIBC = 0xB1000000n;

  // ---- ELF relocations ----
  const e_shoff = Number(SO.readBigUInt64LE(40));
  const e_shentsize = SO.readUInt16LE(58), e_shnum = SO.readUInt16LE(60), e_shstrndx = SO.readUInt16LE(62);
  const shOffOf = (i) => Number(SO.readBigUInt64LE(e_shoff + i * e_shentsize + 24));
  const shSizeOf = (i) => Number(SO.readBigUInt64LE(e_shoff + i * e_shentsize + 32));
  const shNameOf = (i) => SO.readUInt32LE(e_shoff + i * e_shentsize);
  let shstrtab = null;
  for (let i = 0; i < e_shnum; i++) if (i === e_shstrndx) shstrtab = SO.slice(shOffOf(i), shOffOf(i) + shSizeOf(i));
  const secName = (i) => { const off = shNameOf(i); const end = shstrtab.indexOf(0, off); return shstrtab.slice(off, end).toString(); };
  let dynsymSec = -1, dynstrSec = -1, relaDyn = -1, relaPlt = -1, gotPlt = -1;
  for (let i = 0; i < e_shnum; i++) {
    const nm = secName(i);
    if (nm === '.dynsym') dynsymSec = i;
    if (nm === '.dynstr') dynstrSec = i;
    if (nm === '.rela.dyn') relaDyn = i;
    if (nm === '.rela.plt') relaPlt = i;
  }
  const dynstr = SO.slice(shOffOf(dynstrSec), shOffOf(dynstrSec) + shSizeOf(dynstrSec));
  const symName = (o) => { const no = SO.readUInt32LE(shOffOf(dynsymSec) + o * 24); const end = dynstr.indexOf(0, no); return dynstr.slice(no, end).toString(); };
  const symVal = (o) => Number(SO.readBigUInt64LE(shOffOf(dynsymSec) + o * 24 + 8));

  const libcHandlers = {}; // magic addr -> fn
  let magicCounter = 0;
  function setGot(addr, magic, fn) { wr64(addr, magic); libcHandlers[magic] = fn; }
  function processRela(secIdx, isPlt) {
    if (secIdx < 0) return;
    const rOff = shOffOf(secIdx), rSize = shSizeOf(secIdx);
    for (let o = 0; o < rSize; o += 24) {
      const rOffset = Number(SO.readBigUInt64LE(rOff + o));
      const info = Number(SO.readBigUInt64LE(rOff + o + 8));
      const addend = Number(SO.readBigUInt64LE(rOff + o + 16));
      const symIdx = Math.floor(info / 4294967296);
      const type = info % 4294967296;
      if (type === 1027) { wr64(rOffset, addend); continue; } // RELATIVE
      if (type === 1025 || type === 1026 || type === 257) {
        const sv = symIdx ? symVal(symIdx) : 0;
        if (sv) { wr64(rOffset, sv + (type === 257 ? addend : 0)); continue; }
        const nm = symIdx ? symName(symIdx) : 'unknown';
        const magic = MAGIC_LIBC + BigInt(magicCounter++);
        setGot(rOffset, magic, nm);
      }
      if (type === 1024) { const sv = symIdx ? symVal(symIdx) : 0; if (sv) wr64(rOffset, sv); continue; } // ABS64
    }
  }
  processRela(relaPlt, true);
  processRela(relaDyn, false);

  // ---- libc + JNI implementations ----
  const regs = new Array(31).fill(0n);
  let pc = 0;
  let exitResult = null;
  const nameForMagic = {};
  function readCStr(addr) {
    addr = Number(addr);
    let s = '';
    for (let i = addr; buf[i] !== 0; i++) s += String.fromCharCode(buf[i]);
    return s;
  }
  function writeCStr(addr, str) {
    addr = Number(addr);
    for (let i = 0; i < str.length; i++) buf[addr + i] = str.charCodeAt(i) & 0xff;
    buf[addr + str.length] = 0;
    return addr;
  }
  function jstringFor(token) {
    const idx = Number(token - 0x3000n);
    return opts.jstrings[idx] || '';
  }

  // fake FILE I/O backing store — used by fopen/fgets/fread stubs below
  const fileTable = new Map();
  let fileMagic = 0x3100000n;
  // real fd table for syscall-level I/O (openat/read/lseek/pread64/mmap)
  const fdTable = new Map();
  let fdCounter = 3;
  function openEntry(p) {
    let content = null;
    if (opts.filesBinary && Object.prototype.hasOwnProperty.call(opts.filesBinary, p)) content = opts.filesBinary[p];
    else if (opts.files && Object.prototype.hasOwnProperty.call(opts.files, p)) content = Buffer.from(opts.files[p]);
    (globalThis.__fileOpens = globalThis.__fileOpens || []).push(p + (Buffer.isBuffer(content) ? ' [HIT]' : ' [MISS]'));
    if (!Buffer.isBuffer(content)) return null;
    return { content, pos: 0 };
  }
  function normPtr(p) { p = BigInt(p) & 0xffffffffffffffffn; return p > 0x4000000n ? (p & 0xffffffffn) : p; }
  const libcFns = {
    malloc: (n) => { const nn = Number(n); const p = heapPtr; heapPtr += BigInt(nn > 0 && nn <= 0x1000000 ? Math.max(16, nn) : 16); return p; },
    free: () => 0n,
    realloc: (p, n) => { const np = heapPtr; heapPtr += BigInt(Math.max(16, Number(n))); const cnt = Number(n); for (let i = 0; i < cnt && i < 4096; i++) buf[Number(np) + i] = buf[Number(p) + i]; return np; },
    calloc: (n, m) => { const p = heapPtr; heapPtr += BigInt(Math.max(16, Number(n * m))); return p; },
    memcpy: (d, s, n) => { buf.copy(buf, Number(d), Number(s), Number(s) + Number(n)); return d; },
    memmove: (d, s, n) => { const tmp = Buffer.from(buf.slice(Number(s), Number(s) + Number(n))); tmp.copy(buf, Number(d)); return d; },
    memset: (d, c, n) => { buf.fill(Number(c) & 0xff, Number(d), Number(d) + Number(n)); return d; },
    strlen: (s) => BigInt(readCStr(s).length),
    __strlen_chk: (s, m) => BigInt(readCStr(s).length),
    __memcpy_chk: (d, s, n, m) => { buf.copy(buf, Number(d), Number(s), Number(s) + Number(n)); return d; },
    __memmove_chk: (d, s, n) => { const tmp = Buffer.from(buf.slice(Number(s), Number(s) + Number(n))); tmp.copy(buf, Number(d)); return d; },
    __strchr_chk: (s, c, m) => { const str = readCStr(s); const i = str.indexOf(String.fromCharCode(Number(c))); return i < 0 ? 0n : s + BigInt(i); },
    strcmp: (a, b) => { const x = readCStr(a), y = readCStr(b); return BigInt(x < y ? -1 : x > y ? 1 : 0); },
    strncmp: (a, b, n) => { const x = readCStr(a).slice(0, Number(n)), y = readCStr(b).slice(0, Number(n)); return BigInt(x < y ? -1 : x > y ? 1 : 0); },
    memcmp: (a, b, n) => { for (let i = 0; i < Number(n); i++) { const x = buf[Number(a) + i], y = buf[Number(b) + i]; if (x !== y) return BigInt(x < y ? -1 : 1); } return 0n; },
    memchr: (s, c, n) => { for (let i = 0; i < Number(n); i++) if (buf[Number(s) + i] === (Number(c) & 0xff)) return s + BigInt(i); return 0n; },
    strstr: (h, n) => { const i = readCStr(h).indexOf(readCStr(n)); return i < 0 ? 0n : h + BigInt(i); },
    abort: () => { throw new Error('abort() called at pc=0x' + pc.toString(16)); },
    __stack_chk_fail: () => { throw new Error('stack_chk_fail at pc=0x' + pc.toString(16)); },
    // fake FILE I/O backed by opts.files { path: content } — used e.g. for /proc/self/maps anti-tamper scans
    fclose: (f) => { fileTable.delete(f); return 0n; },
    fopen: (path, mode) => { const entry = openEntry(readCStr(normPtr(path))); if (!entry) return 0n; fileMagic += 16n; fileTable.set(fileMagic, entry); return fileMagic; },
    fgets: (s, n, f) => { const fh = fileTable.get(f); if (!fh) return 0n; const c = fh.content; if (fh.pos >= c.length) return 0n; let line = ''; while (fh.pos < c.length && c[fh.pos] !== 10) { line += String.fromCharCode(c[fh.pos]); fh.pos++; } fh.pos++; writeCStr(s, line); return s; },
    fread: (ptr, size, nmemb, f) => { const fh = fileTable.get(f); if (!fh) return 0n; const want = Number(size) * Number(nmemb); const total = Math.min(want, fh.content.length - fh.pos); for (let i = 0; i < total; i++) buf[Number(ptr) + i] = fh.content[fh.pos + i]; fh.pos += total; return BigInt(Math.floor(total / Number(size))); },
    fseek: (f, off, whence) => { const fh = fileTable.get(f); if (fh) { const w = Number(whence); if (w === 1) fh.pos += Number(off); else if (w === 2) fh.pos = fh.content.length + Number(off); else fh.pos = Number(off); } return 0n; },
    ftell: (f) => { const fh = fileTable.get(f); return BigInt(fh ? fh.pos : 0); },
    lseek: (fd, off, whence) => { const e = fdTable.get(Number(fd)); if (!e) return -1n; if (Number(whence) === 1) e.pos += Number(off); else if (Number(whence) === 2) e.pos = e.content.length + Number(off); else e.pos = Number(off); return BigInt(e.pos); },
    read: (fd, ptr, n) => { const e = fdTable.get(Number(fd)); if (!e) return -1n; const total = Math.min(Number(n), e.content.length - e.pos); for (let i = 0; i < total; i++) buf[Number(ptr) + i] = e.content[e.pos + i]; e.pos += total; return BigInt(total); },
    close: (fd) => { fdTable.delete(Number(fd)); return 0n; },
    fdopen: (fd) => { const e = fdTable.get(Number(fd)); if (!e) return 0n; fileMagic += 16n; fileTable.set(fileMagic, e); return fileMagic; },
    syscall: (n, a, b, c, d, e, f) => {
      const num = Number(n);
      if (num === 56) { const entry = openEntry(readCStr(normPtr(b))); if (!entry) return -1n; const fd = fdCounter++; fdTable.set(fd, entry); return BigInt(fd); }
      if (num === 57) { fdTable.delete(Number(b)); return 0n; }
      if (num === 63) return libcFns.read(b, c, d);
      if (num === 62) return libcFns.lseek(b, c, d);
      if (num === 67) { const en = fdTable.get(Number(b)); if (!en) return -1n; const off = Number(f || 0n); const total = Math.min(Number(d), en.content.length - off); for (let i = 0; i < total; i++) buf[Number(c) + i] = en.content[off + i]; return BigInt(total); }
      if (num === 80) { const en = fdTable.get(Number(b)); if (!en) return -1n; const st = Number(c); buf.fill(0, st, st + 128); buf.writeBigUInt64LE(BigInt(en.content.length), st + 48); return 0n; }
      if (num === 222) { const en = fdTable.get(Number(e)); if (!en) return -1n; const len = Number(b); const p = heapPtr; heapPtr += BigInt((len + 0xfff) & ~0xfff); const off = Number(f || 0n); const cp = Math.min(len, en.content.length - off); for (let i = 0; i < cp; i++) buf[Number(p) + i] = en.content[off + i]; return p; }
      if (num === 215 || num === 226 || num === 227) return 0n;
      return 0n;
    },
    __errno: () => 0x3000000n,
    posix_memalign: () => 0n,
    snprintf: (...a) => { let k = 3; const args = []; const out = formatC(readCStr(a[2]), () => { const v = k < a.length ? a[k++] : 0n; args.push(v); return v; }); writeCStr(a[0], out); (globalThis.__fmtCalls = globalThis.__fmtCalls || []).push({ fmt: readCStr(a[2]), out, rawArgs: args.map(String) }); return BigInt(out.length); },
    __vsnprintf_chk: (s, n, f, o, fmt, va) => {
      // AArch64 va_list struct: { void* __stack; void* __gr_top; void* __vr_top; int __gr_offs; int __vr_offs; }
      const vaBase = Number(va);
      let stackPtr = rd64(vaBase);
      const grTop = rd64(vaBase + 8);
      let grOffs = rd32(vaBase + 24) | 0;
      const nextArg = () => {
        if (grOffs < 0) { const a = rd64(grTop + BigInt(grOffs)); grOffs += 8; return a; }
        const a = rd64(stackPtr); stackPtr += 8n; return a;
      };
      const raw = [];
      const wrapped = () => { const v = nextArg(); raw.push(v); return v; };
      const out = formatC(readCStr(fmt), wrapped);
      writeCStr(s, out);
      (globalThis.__fmtCalls = globalThis.__fmtCalls || []).push({ fmt: readCStr(fmt), out, rawArgs: raw.map(String) });
      return BigInt(out.length);
    },
    __cxa_atexit: () => 0n, __cxa_finalize: () => 0n, __register_atfork: () => 0n,
    pthread_mutex_lock: () => 0n, pthread_mutex_unlock: () => 0n,
    pthread_getspecific: () => 0n, pthread_setspecific: () => 0n, pthread_once: () => 0n,
    getauxval: () => 0n, __system_property_get: () => 0n,
    _Znwm: (n) => libcFns.malloc(n), _Znam: (n) => libcFns.malloc(n), _ZdlPv: () => 0n, _ZdaPv: () => 0n,
    _ZnwmSt11align_val_t: (n) => libcFns.malloc(n), _ZnamSt11align_val_t: (n) => libcFns.malloc(n),
    _ZdlPvSt11align_val_t: () => 0n, _ZdaPvSt11align_val_t: () => 0n,
    __cxa_allocate_exception: (n) => libcFns.malloc(n),
    __cxa_throw: () => { throw new Error('cxa_throw at pc=0x' + pc.toString(16)); },
    _ZSt15get_new_handlerv: () => 0n, _ZSt9terminatev: () => { throw new Error('terminate'); },
    __cxa_begin_catch: () => 0n, __cxa_end_catch: () => 0n, __cxa_free_exception: () => 0n,
    __cxa_demangle: () => 0n, __cxa_call_unexpected: () => { throw new Error('unexpected'); },
    __cxa_get_globals: () => libcFns.malloc(256n), __cxa_get_globals_fast: () => libcFns.malloc(256n),
    __cxa_rethrow: () => { throw new Error('rethrow'); },
    __emutls_get_address: () => libcFns.malloc(256n),
    vfprintf: () => 0n, fputc: () => 0n, fflush: () => 0n, fwrite: () => 0n, vasprintf: () => 0n,
    openlog: () => 0n, syslog: () => 0n, closelog: () => 0n, android_set_abort_message: () => 0n,
    wcslen: (s) => { let i = 0; while (rd32(Number(s) + i * 4) !== 0) i++; return BigInt(i); },
    wmemcpy: (d, s, n) => { for (let i = 0; i < Number(n); i++) wr32(Number(d) + i * 4, rd32(Number(s) + i * 4)); return d; },
    wmemmove: (d, s, n) => { const t = []; for (let i = 0; i < Number(n); i++) t.push(rd32(Number(s) + i * 4)); for (let i = 0; i < Number(n); i++) wr32(Number(d) + i * 4, t[i]); return d; },
    wmemset: (d, c, n) => { for (let i = 0; i < Number(n); i++) wr32(Number(d) + i * 4, Number(c)); return d; },
    wmemchr: (s, c, n) => { for (let i = 0; i < Number(n); i++) if (rd32(Number(s) + i * 4) === Number(c)) return s + BigInt(i * 4); return 0n; },
    wmemcmp: (a, b, n) => { for (let i = 0; i < Number(n); i++) { const x = rd32(Number(a) + i * 4), y = rd32(Number(b) + i * 4); if (x !== y) return BigInt(x < y ? -1 : 1); } return 0n; },
    strtoul: (s) => { const v = parseInt(readCStr(s)); return BigInt(v || 0); },
    strtoull: (s) => { const v = parseInt(readCStr(s)); return BigInt(v || 0); },
    strtoll: (s) => { const v = parseInt(readCStr(s)); return BigInt(v || 0); },
    strtol: (s) => { const v = parseInt(readCStr(s)); return BigInt(v || 0); },
    strtof: () => 0n, strtod: () => 0n, strtold: () => 0n,
    _ZNSt6__ndk16__itoa8__u32toaEjPc: (v, b) => { writeCStr(b, String(Number(v))); return b; },
    _ZNSt6__ndk16__itoa8__u64toaEmPc: (v, b) => { writeCStr(b, String(Number(v))); return b; },
  };
  // printf-style formatter — nextArg() yields successive varargs as BigInts
  function formatC(fmt, nextArg) {
    let out = '';
    let i = 0;
    while (i < fmt.length) {
      const ch = fmt[i];
      if (ch !== '%') { out += ch; i++; continue; }
      if (fmt[i + 1] === '%') { out += '%'; i += 2; continue; }
      let j = i + 1;
      let flags = '';
      while (j < fmt.length && '-+ #0'.indexOf(fmt[j]) >= 0) { flags += fmt[j]; j++; }
      let width = '';
      while (j < fmt.length && fmt[j] >= '0' && fmt[j] <= '9') { width += fmt[j]; j++; }
      if (fmt[j] === '*') { width = String(Number(nextArg())); j++; }
      let prec = '';
      if (fmt[j] === '.') {
        j++;
        if (fmt[j] === '*') { prec = String(Number(nextArg())); j++; }
        else while (j < fmt.length && fmt[j] >= '0' && fmt[j] <= '9') { prec += fmt[j]; j++; }
      }
      while (j < fmt.length && 'hlLqjzt'.indexOf(fmt[j]) >= 0) j++;
      const conv = fmt[j];
      j++;
      if (conv === undefined) break;
      const w = width ? parseInt(width) : 0;
      const p = prec ? parseInt(prec) : -1;
      const arg = nextArg();
      let str;
      switch (conv) {
        case 'd': case 'i': {
          let v = BigInt.asIntN(64, BigInt(arg));
          str = (v < 0n ? '-' : (flags.indexOf('+') >= 0 ? '+' : '')) + (v < 0n ? (-v).toString() : v.toString());
          break;
        }
        case 'u': str = BigInt.asUintN(64, BigInt(arg)).toString(); break;
        case 'x': str = BigInt.asUintN(64, BigInt(arg)).toString(16); break;
        case 'X': str = BigInt.asUintN(64, BigInt(arg)).toString(16).toUpperCase(); break;
        case 'p': str = '0x' + BigInt.asUintN(64, BigInt(arg)).toString(16); break;
        case 'c': str = String.fromCharCode(Number(BigInt.asUintN(64, BigInt(arg)) & 0xffn)); break;
        case 's': { str = readCStr(arg); if (p >= 0) str = str.substring(0, p); break; }
        case 'f': case 'g': case 'e': str = String(arg); break;
        default: str = '';
      }
      if (w > 0 && str.length < w) {
        const zeroPad = flags.indexOf('0') >= 0 && conv !== 's' && conv !== 'c' && prec === '' && flags.indexOf('-') < 0;
        const need = w - str.length;
        if (flags.indexOf('-') >= 0) str = str + ' '.repeat(need);
        else if (zeroPad && (str[0] === '-' || str[0] === '+')) str = str[0] + '0'.repeat(need) + str.slice(1);
        else str = (zeroPad ? '0' : ' ').repeat(need) + str;
      }
      out += str;
      i = j;
    }
    return out;
  }

  // set JNIEnv table
  wr64(ENV, JNITABLE);
  function jni(magicAddr, fn) { wr64(JNITABLE + magicAddr, MAGIC_F + BigInt(magicAddr)); libcHandlers[MAGIC_F + BigInt(magicAddr)] = fn; }
  jni(1352n, (env, jstr) => { const s = jstringFor(jstr); const p = heapPtr; heapPtr += BigInt(s.length + 1); writeCStr(p, s); opts._lastGetStringPtr = p; (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetStringUTFChars(0x' + jstr.toString(16) + ')="' + s + '" @pc=0x' + pc.toString(16) }); return p; }); // GetStringUTFChars
  jni(1360n, () => 0n); // ReleaseStringUTFChars
  jni(1336n, (env, cstr) => { const s = readCStr(cstr); (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'NewStringUTF', value: s, pc: '0x' + pc.toString(16) }); (globalThis.__newStrings = globalThis.__newStrings || []).push({ s, pc: '0x' + pc.toString(16) }); if (!opts.collectStrings) exitResult = s; return 0x4000n; }); // NewStringUTF
  jni(1360n + 0n, () => 0n);

  // ---- Real JNI semantics for the calls Iron makes ----
  // GetObjectClass = slot 31 (0xF8), GetMethodID = slot 33 (0x108),
  // CallObjectMethod = slot 34 (0x110), CallObjectMethodV = slot 35 (0x118)
  // (JNI table: 4 reserved + PushLocalFrame/PopLocalFrame shift everything by 2 slots
  //  relative to the frequently-quoted numbering.)
  const classToken = 0x2000n;
  let methodCounter = 0x8000n;
  const methodTokenByName = {};
  const methodNameByToken = {};
  const jstringOf = (s) => {
    opts.jstrings.push(s);
    return 0x3000n + BigInt(opts.jstrings.length - 1);
  };
  const callObjectMethod = (env, obj, methodToken) => {
    const name = methodNameByToken[Number(methodToken)];
    const pcAt = 'pc=0x' + pc.toString(16);
    let value = '';
    if (name === 'getPackageName') value = opts.packageName || 'com.drama.mp4';
    else if (name === 'getPackageCodePath') value = opts.codePath || '/data/app/~~xyz/com.drama.mp4-AbCdEf/base.apk';
    else if (name === 'getFilesDir') value = '/data/user/0/com.drama.mp4/files';
    else if (name === 'toString') value = '';
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: name, value, pcAt });
    // non-string object results: PackageManager / PackageInfo / Signature chain
    if (name === 'getPackageManager') return 0x2200n; // PackageManager token
    if (name === 'getPackageInfo') return 0x2300n; // PackageInfo token
    if (name === 'getApkContentsSigners' || name === 'getSigningCertificateHistory') return 0x2400n; // Signature[] token
    if (name === 'toByteArray') return 0x2700n; // byte[] token (certificate raw bytes)
    if (name === 'toCharsString') { const hex = (globalThis.__sigCertHex || ''); return hex ? jstringOf(hex) : 0n; }
    return value ? jstringOf(value) : 0n;
  };
  jni(248n, (env, obj) => classToken); // GetObjectClass (slot 31)
  jni(264n, (env, clazz, namePtr, sigPtr) => { // GetMethodID (slot 33)
    const nm = readCStr(namePtr);
    if (!methodTokenByName[nm]) { methodTokenByName[nm] = methodCounter; methodNameByToken[Number(methodCounter)] = nm; methodCounter++; }
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetMethodID=' + nm + ':' + readCStr(sigPtr) + ' @pc=0x' + pc.toString(16) });
    return BigInt(methodTokenByName[nm]);
  });
  jni(272n, callObjectMethod); // CallObjectMethod (slot 34)
  jni(280n, callObjectMethod); // CallObjectMethodV (slot 35)
  jni(1824n, (env, obj) => { // GetObjectRefType: valid only for our token space (real .rodata ptrs are invalid refs)
    // at these pcs the library probes a raw pointer that is NOT a jobject on a real device → invalid ref (0)
    if ([0x1f818, 0x1f898, 0x1f960, 0x1faac, 0x1eee0].includes(pc)) { (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetObjectRefType(0x' + obj.toString(16) + ')=0 (pc-site) @pc=0x' + pc.toString(16) }); return 0n; }
    const r = (obj >= 0x2000n && obj < 0x4000n) ? 1n : 0n;
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetObjectRefType(0x' + obj.toString(16) + ')=' + r + ' @pc=0x' + pc.toString(16) });
    return r;
  });
  // FindClass (slot 6): return a stable class token; remember name for field/method lookups
  const classTokenByName = {};
  let classCounter = 0x2500n;
  jni(48n, (env, namePtr) => { // slot 6 = FindClass
    const nm = readCStr(namePtr);
    if (!classTokenByName[nm]) { classTokenByName[nm] = classCounter; classCounter += 16n; }
    return classTokenByName[nm];
  });
  // GetStaticFieldID (slot 144) / GetStaticIntField (slot 150) — empirically confirmed slots
  const staticFieldValues = { SDK_INT: 34 };
  const fieldTokenByName = {};
  let fieldCounter = 0x6000n;
  jni(1152n, (env, clazz, namePtr, sigPtr) => { // slot 144
    const nm = readCStr(namePtr);
    if (!fieldTokenByName[nm]) { fieldTokenByName[nm] = fieldCounter; fieldCounter += 8n; }
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetStaticFieldID=' + nm + ':' + readCStr(sigPtr) });
    return fieldTokenByName[nm];
  });
  jni(1200n, (env, clazz, fieldToken) => { // slot 150 = GetStaticIntField
    const nm = Object.keys(fieldTokenByName).find(k => fieldTokenByName[k] === fieldToken) || '?';
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetStaticIntField(' + nm + ')=' + (staticFieldValues[nm] != null ? staticFieldValues[nm] : 0) });
    return BigInt(staticFieldValues[nm] != null ? staticFieldValues[nm] : 0);
  });
  // instance fields (slots 94/95) + array access (slots 171/173) — PackageInfo.signatures chain
  const instFieldTokenByName = {};
  let instFieldCounter = 0x7000n;
  const SIGNATURE_ARRAY_TOKEN = 0x2400n;
  const SIGNATURE_OBJ_TOKEN = 0x2500n;
  jni(752n, (env, clazz, namePtr, sigPtr) => { // slot 94 = GetFieldID
    const nm = readCStr(namePtr);
    if (!instFieldTokenByName[nm]) { instFieldTokenByName[nm] = instFieldCounter; instFieldCounter += 8n; }
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetFieldID=' + nm + ':' + readCStr(sigPtr) + ' @pc=0x' + pc.toString(16) });
    return instFieldTokenByName[nm];
  });
  jni(760n, (env, obj, fieldToken) => { // slot 95 = GetObjectField
    const nm = Object.keys(instFieldTokenByName).find(k => instFieldTokenByName[k] === fieldToken) || '?';
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetObjectField(' + nm + ') @pc=0x' + pc.toString(16) });
    if (nm === 'signatures' || nm === 'signingInfo') return nm === 'signingInfo' ? 0x2600n : SIGNATURE_ARRAY_TOKEN;
    return 0n;
  });
  const certBytes = () => Buffer.from((globalThis.__sigCertHex || ''), 'hex');
  jni(1368n, (env, array) => { // slot 171 = GetArrayLength
    const len = BigInt(array) === 0x2700n ? BigInt(certBytes().length) : 1n;
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetArrayLength(len=' + len + ') @pc=0x' + pc.toString(16) });
    return len;
  });
  jni(1472n, (env, arr, isCopyPtr) => { // slot 184 = GetByteArrayElements
    const bytes = certBytes();
    const p = heapPtr; heapPtr += BigInt(Math.max(16, bytes.length));
    for (let i = 0; i < bytes.length; i++) buf[Number(p) + i] = bytes[i];
    if (Number(isCopyPtr)) wr32(isCopyPtr, 0); // JNI_FALSE — direct pointer
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetByteArrayElements(len=' + bytes.length + ') @pc=0x' + pc.toString(16) });
    return p;
  });
  jni(1536n, () => 0n); // slot 192 = ReleaseByteArrayElements
  jni(1384n, (env, array, index) => { // slot 173 = GetObjectArrayElement
    (globalThis.__jniCalls = globalThis.__jniCalls || []).push({ resolved: 'GetObjectArrayElement[' + index + '] @pc=0x' + pc.toString(16) });
    return SIGNATURE_OBJ_TOKEN;
  });

  // Generic JNI slot instrumentation: stub every other table slot with a logger
  // so we can discover which JNIEnv functions the library actually calls.
  for (let slot = 4; slot <= 230; slot++) {
    const off = BigInt(slot * 8);
    if (libcHandlers[MAGIC_F + off]) continue;
    jni(off, (...a) => {
      const desc = {
        slot,
        callPc: '0x' + pc.toString(16),
        off: '0x' + (slot * 8).toString(16),
        args: a.map((x) => {
          try {
            if (typeof x === 'bigint' && x > 0x1000n && x < 0x400000n) {
              let s = '';
              const base = Number(x);
              for (let i = 0; i < 256 && buf[base + i] !== 0; i++) s += String.fromCharCode(buf[base + i]);
              if (s.length > 1) return 'str:"' + s + '"';
            }
          } catch (e) { /* ignore */ }
          return typeof x === 'bigint' ? '0x' + x.toString(16) : String(x);
        }),
      };
      (globalThis.__jniCalls = globalThis.__jniCalls || []).push(desc);
      return 0n;
    });
  }

  // resolve magic names to functions
  globalThis.__libcCalls = [];
  for (const [magic, nm] of Object.entries(libcHandlers)) {
    if (typeof nm === 'string') {
      const fn = libcFns[nm];
      libcHandlers[BigInt(magic)] = fn ? (...a) => { if (opts.logCalls) globalThis.__libcCalls.push(nm + '(' + a.map(x => (typeof x === 'bigint' ? '0x' + x.toString(16) : String(x))).join(',') + ') @' + pc.toString(16)); return fn(...a); } : (...a) => { throw new Error('unimplemented libc: ' + nm + ' at pc=0x' + pc.toString(16)); };
    }
  }

  // ---- helpers ----
  const MASK64 = 0xffffffffffffffffn;
  const s64 = (v) => { v &= MASK64; return v >= 0x8000000000000000n ? v - 0x10000000000000000n : v; };
  const s32 = (v) => { v = Number(v) & 0xffffffff; return v >= 0x80000000 ? v - 0x100000000 : v; };
  function rreg(i) { return i === 31 ? regs[31] : regs[i]; }
  function wreg(i, v) { regs[i === 31 ? 31 : i] = BigInt(v) & MASK64; if (opts.watchVal !== undefined && (BigInt(v) & MASK64) === BigInt(opts.watchVal)) (globalThis.__regWatch = globalThis.__regWatch || []).push('w pc=0x' + pc.toString(16)); if (opts.traceReg === i) (globalThis.__regWrites = globalThis.__regWrites || []).push({ pc: '0x' + pc.toString(16), val: (BigInt(v) & MASK64).toString(16) }); }
  // In ALU (non load/store, non immediate/extended add-sub) encodings, reg 31 = ZR, not SP
  function rregZ(i) { return i === 31 ? 0n : regs[i]; }
  function wregZ(i, v) { if (i !== 31) { regs[i] = BigInt(v) & MASK64; if (opts.watchVal !== undefined && (BigInt(v) & MASK64) === BigInt(opts.watchVal)) (globalThis.__regWatch = globalThis.__regWatch || []).push('wz pc=0x' + pc.toString(16)); if (opts.traceReg === i) (globalThis.__regWrites = globalThis.__regWrites || []).push({ pc: '0x' + pc.toString(16), val: (BigInt(v) & MASK64).toString(16) }); } }
  const SP = () => regs[31];

  function highestSetBit(v) { return 31 - Math.clz32(v); }
  function decodeLI(N, immr, imms, datasize) {
    const notImmS = (~imms) & 0x3f;
    const prefix = N ? (notImmS | 0x40) : notImmS;
    if (prefix === 0) throw new Error('reserved LI');
    const len = 31 - Math.clz32(prefix);
    const levels = len === 6 ? 63 : (1 << len) - 1;
    const S = imms & levels, R = immr & levels;
    const esizeN = 1 << len;
    const esize = BigInt(esizeN);
    const welem = (1n << BigInt(S + 1)) - 1n;
    let telem;
    if (R === 0) telem = welem;
    else telem = ((welem << (esize - BigInt(R))) | (welem >> BigInt(R))) & ((1n << esize) - 1n);
    let res = 0n;
    const reps = BigInt(datasize) / esize;
    for (let i = 0n; i < reps; i++) res |= telem << (esize * i);
    return res;
  }

  // SIMD vregs: 128-bit as {lo,hi} BigInt pairs
  const vregs = new Array(32).fill(null).map(() => ({ lo: 0n, hi: 0n }));
  function vwrite(i, lo, hi) { vregs[i].lo = BigInt(lo) & MASK64; vregs[i].hi = BigInt(hi) & MASK64; }

  let steps = 0;
  const maxSteps = opts.maxSteps || 50_000_000;
  const trace = opts.trace || null;

  function getShifted(rn, rm, shiftType, amount, sf) {
    let v = rregZ(rm);
    if (!sf) v &= 0xffffffffn;
    const bits = sf ? 64n : 32n;
    if (shiftType === 0) v = v << BigInt(amount);
    else if (shiftType === 1) v = v >> BigInt(amount);
    else if (shiftType === 2) v = s64(v) >> BigInt(amount);
    else { // ror
      const amt = BigInt(amount) % bits;
      v = amt === 0n ? v : ((v >> amt) | (v << (bits - amt)));
    }
    return v & (sf ? MASK64 : 0xffffffffn);
  }
  function getExtend(rm, opt, amount, sf) {
    let v = rregZ(rm);
    if (opt === 0) v = v & 0xffffffffn; // UXTB
    else if (opt === 1) v = BigInt(Number(v) & 0xffff); // UXTH
    else if (opt === 2) v = BigInt(Number(v) & 0xff); // UXTW
    else if (opt === 3) { } // UXTX
    else if (opt === 4) v = BigInt(Number(v) & 0xff) | ((Number(v) & 0x80) ? 0xffffff00n : 0n); // SXTB
    else if (opt === 5) v = BigInt(Number(v) & 0xffff) | ((Number(v) & 0x8000) ? 0xffff0000n : 0n); // SXTH
    else if (opt === 6) v = s32(v) | 0n; // SXTW
    if (opt <= 3 && opt !== 3) { if (amount) v = v << BigInt(amount); }
    return v;
  }

  function step() {
    const insn = rd32(pc);
    steps++;
    if (steps > maxSteps) throw new Error('step limit at pc=0x' + pc.toString(16));
    if (trace) trace(pc, insn);
    const top9 = (insn >>> 23) & 0x1ff;
    const op = insn >>> 24;

    // --- branches ---
    if (((insn & 0x7c000000) >>> 0) === 0x14000000) { // B / BL (bit31 = link)
      const off = (insn & 0x3ffffff) << 2;
      const offSigned = (off << 6 >> 6);
      if (insn & 0x80000000) regs[30] = BigInt(pc + 4);
      pc += offSigned;
      return;
    }
    if ((insn & 0x7e000000) === 0x34000000) { // CBZ/CBNZ
      const is64 = (insn >>> 31) & 1;
      const nz = (insn >>> 24) & 1;
      const rt = insn & 31;
      let v = rreg(rt);
      if (!is64) v &= 0xffffffffn;
      const off = ((insn >> 5) & 0x7ffff) << 2;
      const offSigned = ((insn >> 23) & 1) ? ((off | 0x100000) - 0x200000) : off;
      if ((v !== 0n) === !!nz) pc += offSigned; else pc += 4;
      return;
    }
    if ((insn & 0x7e000000) === 0x36000000) { // TBZ/TBNZ
      const is64 = (insn >>> 31) & 1;
      const nz = (insn >>> 24) & 1;
      const rt = insn & 31;
      const bit = ((insn >>> 19) & 0x1f) | (((insn >>> 31) & 1) << 5);
      const v = rreg(rt);
      const bitSet = ((v >> BigInt(bit)) & 1n) === 1n;
      const off = ((insn >> 5) & 0x3fff) << 2;
      const offSigned = (off << 16 >> 16); // sign bit is bit 18 of imm14 (bit 20 of the shifted offset)
      if (bitSet === !!nz) pc += offSigned; else pc += 4;
      return;
    }
    if ((insn & 0xff000010) === 0x54000000) { // B.cond
      const cond = insn & 0xf;
      if (checkCond(cond)) {
        const off = ((insn >> 5) & 0x7ffff) << 2;
        const offSigned = ((insn >> 23) & 1) ? ((off | 0x100000) - 0x200000) : off;
        pc += offSigned;
      } else pc += 4;
      return;
    }
    if (((insn & 0xfffffc1f) >>> 0) === 0xd65f0000) { pc = Number(regs[30]); return; } // RET
    if (((insn & 0xfffffc1f) >>> 0) === 0xd63f0000) { // BLR
      const target = rreg((insn >> 5) & 31);
      regs[30] = BigInt(pc + 4);
      callMagic(target);
      pc = Number(regs[30]);
      return;
    }
    if (((insn & 0xfffffc1f) >>> 0) === 0xd61f0000) { // BR
      const t = rreg((insn >> 5) & 31);
      if (t >= 0xB0000000n) { callMagic(t); pc = Number(regs[30]); return; } // tail-call to emulated libc/JNI
      pc = Number(t); return;
    }

    // --- hint space (NOP, PAC, BTI) ---
    if ((insn & 0xffffe000) >>> 0 === 0xd5032000) { pc += 4; return; }

    // --- ADRP / ADR ---
    if (((insn & 0x9f000000) >>> 0) === 0x90000000) {
      const rd = insn & 31;
      const immlo = (insn >> 29) & 3, immhi = (insn >> 5) & 0x7ffff;
      let imm = ((immhi << 2) | immlo);
      if (insn & 0x80000000) {
        // ADRP
        const signed = (imm << 13 >> 13);
        wreg(rd, BigInt((pc & ~0xfff) + (signed * 4096)));
      } else {
        const signed = (imm << 13 >> 13);
        wreg(rd, BigInt(pc + signed));
      }
      pc += 4; return;
    }

    // --- ADD/SUB immediate ---
    if ((op & 0x1f) === 0x11 && (insn & 0x00800000) === 0) {
      const sf = (insn >>> 31) & 1, sub = (insn >>> 30) & 1, keepFlags = (insn >>> 29) & 1;
      const rd = insn & 31, rn = (insn >> 5) & 31;
      const imm = (insn >> 10) & 0xfff;
      const shift = ((insn >> 22) & 3) === 1 ? 12 : 0;
      let a = rreg(rn); if (!sf) a &= 0xffffffffn;
      let b = BigInt(imm << shift);
      let res = sub ? a - b : a + b;
      if (!sf) res &= 0xffffffffn;
      // ADD/SUB (immediate): rd=31 means SP, but for the flag-setting forms
      // (ADDS/SUBS, incl. CMP) rd=31 means ZR — never write SP there.
      if (keepFlags) { wregZ(rd, res); setFlags(res, a, b, sub, sf); } else wreg(rd, res);
      pc += 4; return;
    }

    // --- MOVZ/MOVN/MOVK ---
    // Real test: bits 28:23 == 100101 (0x25). The old op-byte test wrongly
    // captured every sf=1 logical immediate (AND/ORR/EOR #imm), turning
    // crypto masks into garbage MOVN values.
    if (((insn >>> 23) & 0x3f) === 0x25) {
      const sf = (insn >>> 31) & 1;
      const opc = (insn >>> 29) & 3;
      const hw = (insn >>> 21) & 3;
      const imm16 = (insn >> 5) & 0xffff;
      const rd = insn & 31;
      let cur = rregZ(rd); if (!sf) cur &= 0xffffffffn;
      let v;
      if (opc === 0) v = ~(BigInt(imm16) << BigInt(hw * 16)); // MOVN
      else if (opc === 2) v = BigInt(imm16) << BigInt(hw * 16); // MOVZ
      else { // MOVK
        const bits = sf ? 64 : 32;
        const mask = (0xffffn << BigInt(hw * 16)) & (sf ? MASK64 : 0xffffffffn);
        v = (cur & ~mask) | (BigInt(imm16) << BigInt(hw * 16));
      }
      if (!sf) v &= 0xffffffffn;
      wregZ(rd, v);
      pc += 4; return;
    }

    // --- Logical immediate ---
    if ((op & 0x1f) === 0x12 && (insn & 0x00800000) === 0) {
      const sf = (insn >>> 31) & 1;
      const opc = (insn >>> 29) & 3;
      const rd = insn & 31, rn = (insn >> 5) & 31;
      const N = (insn >>> 22) & 1;
      const immr = (insn >> 16) & 0x3f, imms = (insn >> 10) & 0x3f;
      const mask = decodeLI(N, immr, imms, sf ? 64 : 32);
      let a = rregZ(rn); if (!sf) a &= 0xffffffffn;
      let v;
      if (opc === 0) v = a & mask;
      else if (opc === 1) v = a | mask;
      else if (opc === 2) v = a ^ mask;
      else v = a & mask;
      if (!sf) v &= 0xffffffffn;
      wregZ(rd, v);
      if (opc === 3) setLogicFlags(v, sf);
      pc += 4; return;
    }

    // --- Logical shifted register (bits 23:22 are the shift type — no bit-22 gate) ---
    if ((op & 0x1f) === 0x0a) {
      const sf = (insn >>> 31) & 1;
      const opc2 = ((insn >>> 29) & 3) | (((insn >>> 21) & 1) << 2); // opc + N bit (bit 21)
      const shift = (insn >>> 22) & 3;
      const imm6 = (insn >> 10) & 0x3f;
      const rm = (insn >> 16) & 31, rn = (insn >> 5) & 31, rd = insn & 31;
      const m = getShifted(0, rm, shift, imm6, sf);
      let a = rregZ(rn); if (!sf) a &= 0xffffffffn;
      let v;
      if (opc2 === 1) v = a | m; // ORR
      else if (opc2 === 2) v = a ^ m; // EOR
      else if (opc2 === 0) v = a & m; // AND
      else if (opc2 === 4) v = a & ~m; // BIC
      else if (opc2 === 5) v = a | ~m; // ORN
      else if (opc2 === 6) v = a ^ ~m; // EON
      else if (opc2 === 7) v = a & ~m; // BICS
      else v = a & m; // ANDS
      if (!sf) v &= 0xffffffffn;
      wregZ(rd, v);
      if (opc2 === 7 || opc2 === 3) setLogicFlags(v, sf);
      pc += 4; return;
    }

    // --- ADD/SUB shifted register (bit 21 = 0) ---
    if ((op & 0x1f) === 0x0b && (insn & 0x00200000) === 0) {
      const sf = (insn >>> 31) & 1, sub = (insn >>> 30) & 1, keepFlags = (insn >>> 29) & 1;
      const shift = (insn >>> 22) & 3;
      const imm6 = (insn >> 10) & 0x3f;
      const rm = (insn >> 16) & 31, rn = (insn >> 5) & 31, rd = insn & 31;
      const m = getShifted(0, rm, shift, imm6, sf);
      let a = rregZ(rn); if (!sf) a &= 0xffffffffn;
      let res = sub ? a - m : a + m;
      if (!sf) res &= 0xffffffffn;
      wregZ(rd, res);
      if (keepFlags) setFlags(res, a, m, sub, sf);
      pc += 4; return;
    }

    // --- ADD/SUB extended register (bit 21 = 1) ---
    if ((op & 0x1f) === 0x0b && (insn & 0x00200000) === 0x00200000) {
      const sf = (insn >>> 31) & 1, sub = (insn >>> 30) & 1, keepFlags = (insn >>> 29) & 1;
      const opt = (insn >>> 13) & 7;
      const imm3 = (insn >> 10) & 7;
      const rm = (insn >> 16) & 31, rn = (insn >> 5) & 31, rd = insn & 31;
      const m = getExtend(rm, opt, imm3, sf);
      let a = rreg(rn); if (!sf) a &= 0xffffffffn;
      let res = sub ? a - m : a + m;
      if (!sf) res &= 0xffffffffn;
      // ADD/SUB (extended register): rd=31 is SP only for the non-flag forms
      if (keepFlags) { wregZ(rd, res); setFlags(res, a, m, sub, sf); } else wreg(rd, res);
      pc += 4; return;
    }

    // --- Data-processing 1 source (bfm/shifts/ror etc) ---
    if ((op & 0x1e) === 0x12 && (insn & 0x1f000000) === 0x13000000 || (insn & 0x7f000000) === 0x13000000) {
      // SBFM/UBFM/BFM + 1-source ops
      const sf = (insn >>> 31) & 1;
      const opc = (insn >>> 29) & 3;
      if (opc === 3) {
        // 1-source: ROR, LSR, LSL (as aliases), CLZ, REV, etc.
        const opcode = (insn >>> 10) & 0x3f;
        const rn = (insn >> 5) & 31, rd = insn & 31;
        let v = rregZ(rn); if (!sf) v &= 0xffffffffn;
        const bits = sf ? 64n : 32n;
        let out = 0n;
        switch (opcode) {
          case 0: out = v; break; // RBIT? no — MOVN handled above; this = ?
          case 4: { let r = 0n; let x = v; for (let i = 0; i < Number(bits); i++) { r = (r << 1n) | (x & 1n); x >>= 1n; } out = r; break; } // RBIT
          case 1: { // REV32/REV64/REV
            if (sf) { out = ((v & 0xffn) << 56n) | ((v & 0xff00n) << 40n) | ((v & 0xff0000n) << 24n) | ((v & 0xff000000n) << 8n) | ((v & 0xff00000000n) >> 8n) | ((v & 0xff0000000000n) >> 24n) | ((v & 0xff000000000000n) >> 40n) | (v >> 56n); }
            else { out = ((v & 0xffn) << 24n) | ((v & 0xff00n) << 8n) | ((v & 0xff0000n) >> 8n) | (v >> 24n); }
            break;
          }
          case 3: { // REV16
            if (sf) out = ((v & 0xffn) << 8n) | ((v & 0xff00n) >> 8n) | ((v & 0xff0000n) << 8n) | ((v & 0xff000000n) >> 8n) | ((v & 0xff00000000n) << 8n) | ((v & 0xff0000000000n) >> 8n) | ((v & 0xff000000000000n) << 8n) | ((v & 0xff00000000000000n) >> 8n);
            else out = ((v & 0xffn) << 8n) | ((v & 0xff00n) >> 8n) | ((v & 0xff0000n) << 8n) | ((v & 0xff000000n) >> 8n);
            break;
          }
          case 8: out = BigInt(Math.clz32(Number((v & 0xffffffffn) >>> 0))); break; // CLZ
          case 9: out = BigInt(highestSetBit(Number((v & 0xffffffffn) >>> 0))); break; // CLS
          default: throw new Error('1src opcode ' + opcode + ' pc=0x' + pc.toString(16) + ' insn=0x' + insn.toString(16));
        }
        if (!sf) out &= 0xffffffffn;
        wreg(rd, out);
        pc += 4; return;
      }
      const immr = (insn >> 16) & 0x3f, imms = (insn >> 10) & 0x3f;
      const rn = (insn >> 5) & 31, rd = insn & 31;
      const bits = sf ? 64 : 32;
      let w = rregZ(rn); if (!sf) w &= 0xffffffffn;
      let out = 0n;
      if (opc === 2) { // UBFM: covers LSR, LSL, UXTB/UXTH/UXTW, UBFX
        if (imms >= immr) {
          // extract the field [immr..imms] to the bottom (LSR / UXT* / UBFX)
          const width = imms - immr + 1;
          out = (w >> BigInt(immr)) & (width >= bits ? -1n : ((1n << BigInt(width)) - 1n));
        } else {
          // wraps around: LSL by (bits - immr) (LSL alias immr=bits-shift, imms=bits-shift-1)
          const sh = bits - immr;
          out = (w << BigInt(sh)) & (sf ? MASK64 : 0xffffffffn);
        }
      } else if (opc === 0) { // SBFM: covers SXT*, SBFX, and the shift aliases
        if (imms >= immr) {
          let t = (w >> BigInt(immr));
          const cnt = imms - immr + 1;
          const mask2 = (1n << BigInt(cnt)) - 1n;
          t &= mask2;
          // sign extend from cnt bits
          if (cnt < bits) { const signBit = (t >> BigInt(cnt - 1)) & 1n; if (signBit) t |= ~mask2; }
          out = t & (sf ? MASK64 : 0xffffffffn);
        } else {
          // wraps: left-shift by (bits - immr) (mirrors the UBFM LSL alias)
          const sh = bits - immr;
          out = (w << BigInt(sh)) & (sf ? MASK64 : 0xffffffffn);
        }
      } else { // BFM
        if (!sf) w &= 0xffffffffn;
        const dstOld = rregZ(rd); if (!sf) dstOld &= 0xffffffffn;
        const mask = ((1n << BigInt(imms - immr + 1)) - 1n) << BigInt(immr);
        out = (dstOld & ~mask) | (((w >> BigInt(immr)) << BigInt(immr)) & mask);
      }
      if (!sf) out &= 0xffffffffn;
      wregZ(rd, out);
      pc += 4; return;
    }

    // --- Multiplies (bits 23:21 select: 0=MADD/MSUB, 1=SMULL, 2=SMULH, 5=UMULL, 6=UMULH) ---
    if ((op & 0x1f) === 0x1b) {
      const sf = (insn >>> 31) & 1;
      const rm = (insn >> 16) & 31;
      const rn = (insn >> 5) & 31;
      const ra = (insn >> 10) & 31;
      const rd = insn & 31;
      const sub = (insn >>> 21) & 7;
      const a = rregZ(rn); const b = rregZ(rm);
      let out;
      if (sub === 0) { // MADD/MSUB (o0 = bit 15)
        let x = a; let y = b;
        if (!sf) { x &= 0xffffffffn; y &= 0xffffffffn; }
        let prod = x * y;
        if (!sf) prod &= 0xffffffffn;
        const acc = rregZ(ra);
        const neg = (insn >>> 15) & 1;
        out = neg ? acc - prod : prod + acc;
        if (!sf) out &= 0xffffffffn;
      } else if (sub === 1) { // SMULL: 32x32 signed -> 64
        out = (BigInt(s32(a)) * BigInt(s32(b))) & MASK64;
      } else if (sub === 5) { // UMULL: 32x32 unsigned -> 64
        out = (BigInt(Number(a) & 0xffffffff) * BigInt(Number(b) & 0xffffffff)) & MASK64;
      } else if (sub === 2) { // SMULH: 64x64 signed -> high 64
        const A = s64(a); const B = s64(b);
        out = ((A * B) >> 64n) & MASK64;
      } else if (sub === 6) { // UMULH: 64x64 unsigned -> high 64
        out = ((a * b) >> 64n) & MASK64;
      } else {
        throw new Error('mult sub ' + sub + ' pc=0x' + pc.toString(16) + ' insn=0x' + insn.toString(16));
      }
      wregZ(rd, out);
      pc += 4; return;
    }

    // --- CSEL/CSINC/CSINV/CSNEG --- (CCMP/CCMN handled below — CSEL must not shadow them)
    if ((op & 0x1f) === 0x1a && (insn & 0x7fe00c00) !== 0x7a400000 && (insn & 0x7fe00c00) !== 0x7a000000) {
      const sf = (insn >>> 31) & 1;
      const rm = (insn >> 16) & 31;
      const cond = (insn >> 12) & 0xf;
      const op2 = (insn >>> 10) & 3;
      const rn = (insn >> 5) & 31, rd = insn & 31;
      let a = rregZ(rn); let b = rregZ(rm);
      if (!sf) { a &= 0xffffffffn; b &= 0xffffffffn; }
      let out;
      if (op2 === 0) { // CSEL
        out = checkCond(cond) ? a : b;
      } else if (op2 === 1) { // CSINC
        out = checkCond(cond) ? a : (b + 1n);
      } else if (op2 === 2) { // CSINV
        out = checkCond(cond) ? a : ~b;
      } else { // CSNEG
        out = checkCond(cond) ? a : -b;
      }
      if (!sf) out &= 0xffffffffn;
      wregZ(rd, out);
      pc += 4; return;
    }

    // --- CCMP/CCMN ---
    if ((insn & 0x7fe00c00) === 0x7a400000 || (insn & 0x7fe00c00) === 0x7a000000) {
      const sf = (insn >>> 31) & 1;
      const rm = (insn >> 16) & 31;
      const cond = (insn >> 12) & 0xf;
      const isCmp = ((insn >>> 11) & 1) === 1;
      const sub = (insn >>> 30) & 1;
      const rn = (insn >> 5) & 31;
      const nzcv = (insn >> 0) & 0;
      const immFlag = ((insn >>> 11) & 1) === 0 ? ((insn >>> 10) & 1) : 0;
      // simplified: CCMP reg/imm
      const imm5 = (insn >> 5) & 0x1f;
      const b = immFlag ? BigInt(((insn >> 6) & 0x1f) | (((insn >>> 11) & 1) << 5)) : rregZ(rm);
      let a = rregZ(rn); if (!sf) { a &= 0xffffffffn; }
      if (checkCond(cond)) {
        setFlags(sub ? a - b : a + b, a, b, sub === 1, sf);
      } else {
        // set NZCV from imm5 field (nzcv bits)
        const nzcvBits = (insn >>> 0) & 0;
        // nzcv stored in bits 0-3? Actually bits 0-3 hold nzcv
        const n = (insn & 8) ? 1 : 0, z = (insn & 4) ? 1 : 0, c = (insn & 2) ? 1 : 0, v = (insn & 1) ? 1 : 0;
        flags.N = !!n; flags.Z = !!z; flags.C = !!c; flags.V = !!v;
      }
      pc += 4; return;
    }

    // --- SIMD (checked BEFORE loads/stores: 0x2E-prefix data-processing collides
    //     with the SIMD LDP/STP pair gate in handleMem and would corrupt memory) ---
    if (handleSimd(insn)) { pc += 4; return; }

    // --- Loads/Stores ---
    if (handleMem(insn)) { pc += 4; return; }

    // --- MRS ---
    if (((insn & 0xffe00000) >>> 0) === 0xd5200000) {
      const rd = insn & 31;
      // tpidr_el0: point to TLS scratch area with a canary at +0x28
      wr64(0x3000028, 0x5f3759dfn);
      wreg(rd, 0x3000000n);
      pc += 4; return;
    }

    throw new Error('UNKNOWN insn 0x' + insn.toString(16) + ' at pc=0x' + pc.toString(16) + ' top9=0x' + top9.toString(16));
  }

  // flags
  const flags = { N: false, Z: false, C: false, V: false };
  function setFlags(res, a, b, sub, sf) {
    const mask = sf ? MASK64 : 0xffffffffn;
    const r = res & mask;
    flags.N = ((r >> (sf ? 63n : 31n)) & 1n) === 1n;
    flags.Z = r === 0n;
    if (sub) { flags.C = a >= b; flags.V = (((a ^ b) & (a ^ r)) >> (sf ? 63n : 31n) & 1n) === 1n; }
    else { flags.C = r < a; flags.V = (((a ^ r) & (b ^ r)) >> (sf ? 63n : 31n) & 1n) === 1n; }
  }
  function setLogicFlags(v, sf) {
    const r = BigInt(v) & (sf ? MASK64 : 0xffffffffn);
    flags.N = ((r >> (sf ? 63n : 31n)) & 1n) === 1n;
    flags.Z = r === 0n;
    flags.C = false; flags.V = false;
  }
  function checkCond(cond) {
    switch (cond) {
      case 0: return flags.Z;
      case 1: return !flags.Z;
      case 2: return flags.C;
      case 3: return !flags.C;
      case 4: return flags.N;
      case 5: return !flags.N;
      case 6: return flags.V;
      case 7: return !flags.V;
      case 8: return flags.C && !flags.Z;
      case 9: return !flags.C || flags.Z;
      case 10: return flags.N === flags.V;
      case 11: return flags.N !== flags.V;
      case 12: return !flags.Z && flags.N === flags.V;
      case 13: return flags.Z || flags.N !== flags.V;
      case 14: return true;
      default: return false;
    }
  }

  function addrFor(insn, size2, isWriteback) {
    // compute address for load/store with encoding bits
    return null;
  }

  function handleMem(insn) {
    const op = insn >>> 24;
    const size2 = (insn >>> 30) & 3;
    const vFlag = (insn >>> 26) & 1;
    // LDP/STP
    if ((insn & 0x7c000000) === 0x28000000 || (insn & 0x7c000000) === 0x2c000000) {
      const isSIMD = ((insn >>> 26) & 1) === 1; // V bit
      const sizePair = (insn >>> 30) & 3; // 10 = 64-bit / 128-bit(SIMD), 00 = 32-bit / 64-bit(SIMD)
      const isLoad = (insn >>> 22) & 1;
      const imm7 = (insn >> 15) & 0x7f;
      const immSigned = (imm7 << 25 >> 25);
      const rt2 = (insn >> 10) & 31, rn = (insn >> 5) & 31, rt = insn & 31;
      const mode = (insn >>> 23) & 3; // 01 = post, 10 = offset, 11 = pre
      const scale = isSIMD ? (sizePair === 2 ? 16 : 8) : (sizePair === 2 ? 8 : 4);
      const off = BigInt(immSigned * scale);
      let base = rreg(rn);
      let addr;
      if (mode === 1) { addr = base; wreg(rn, base + off); } // post: access old base, then writeback
      else if (mode === 3) { addr = base + off; wreg(rn, addr); } // pre
      else addr = base + off; // signed offset
      addr &= MASK64; // wrap negative offsets (e.g. base + 0xffff...f9)
      const a1 = Number(addr), a2 = Number(addr) + (isSIMD ? (sizePair === 2 ? 16 : 8) : (sizePair === 2 ? 8 : 4));
      if (isLoad) {
        if (isSIMD) { vwrite(rt, buf.readBigUInt64LE(a1), buf.readBigUInt64LE(a1 + 8)); vwrite(rt2, buf.readBigUInt64LE(a2), buf.readBigUInt64LE(a2 + 8)); }
        else if (sizePair === 2) { // LDP x-regs: 8 bytes each, zero-extended
          wreg(rt, buf.readBigUInt64LE(a1));
          wreg(rt2, buf.readBigUInt64LE(a2));
        } else { // LDP w-regs: 4 bytes each, zero-extended (high 32 bits must NOT leak neighbor data)
          wreg(rt, BigInt(buf.readUInt32LE(a1)));
          wreg(rt2, BigInt(buf.readUInt32LE(a2)));
        }
      } else {
        if (isSIMD) { buf.writeBigUInt64LE(vregs[rt].lo, a1); buf.writeBigUInt64LE(vregs[rt].hi, a1 + 8); buf.writeBigUInt64LE(vregs[rt2].lo, a2); buf.writeBigUInt64LE(vregs[rt2].hi, a2 + 8); }
        else if (sizePair === 2) { buf.writeBigUInt64LE(rregZ(rt) & MASK64, a1); buf.writeBigUInt64LE(rregZ(rt2) & MASK64, a2); }
        else { buf.writeUInt32LE(Number(rregZ(rt) & 0xffffffffn), a1); buf.writeUInt32LE(Number(rregZ(rt2) & 0xffffffffn), a2); }
      }
      return true;
    }
    // unsigned-offset immediate loads/stores (incl SIMD 128-bit)
    if ((insn & 0x3b000000) === 0x39000000 && ((insn >>> 24) & 3) === 1) {
      const isLoad = (insn >>> 22) & 1;
      const isSIMD = ((insn >>> 26) & 1) === 1;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const imm12 = (insn >> 10) & 0xfff;
      const scale = isSIMD ? ((insn >>> 30) & 3) === 2 ? 16 : 8 : (1 << ((insn >>> 30) & 3));
      const addr = Number(rreg(rn)) + imm12 * scale;
      if (isSIMD) {
        if (isLoad) { vwrite(rt, buf.readBigUInt64LE(addr), buf.readBigUInt64LE(addr + 8)); }
        else { buf.writeBigUInt64LE(vregs[rt].lo, addr); buf.writeBigUInt64LE(vregs[rt].hi, addr + 8); }
      } else {
        if (isLoad) {
          if (size2 === 3) wreg(rt, buf.readBigUInt64LE(addr));
          else if (size2 === 2) wreg(rt, buf.readUInt32LE(addr));
          else if (size2 === 1) wreg(rt, buf.readUInt16LE(addr));
          else wreg(rt, buf.readUInt8(addr));
        } else {
          const val = rregZ(rt);
          if (size2 === 3) buf.writeBigUInt64LE(val & MASK64, addr);
          else if (size2 === 2) buf.writeUInt32LE(Number(val & 0xffffffffn), addr);
          else if (size2 === 1) buf.writeUInt16LE(Number(val & 0xffffn), addr);
          else buf.writeUInt8(Number(val & 0xffn), addr);
        }
      }
      return true;
    }
    // unscaled / post / pre loads/stores — bit21=0 (bit21=1 = register-offset, handled below)
    if ((insn & 0x3b200000) === 0x38000000) {
      if (((insn >>> 22) & 3) === 2) return true; // PRFM — prefetch, no memory effect
      const mode = (insn >>> 10) & 3; // bits 11:10 — 0 unscaled, 1 post, 3 pre
      const isLoad = (insn >>> 22) & 1;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const imm9 = (insn >> 12) & 0x1ff;
      const immSigned = (imm9 << 23 >> 23);
      let base = rreg(rn);
      let addr = base + BigInt(immSigned);
      if (mode === 1) addr = base; // post-index: access old base
      if (mode === 3) { wreg(rn, addr); } // pre-index: writeback before access
      addr &= MASK64;
      const a = Number(addr);
      if (isLoad) {
        if (size2 === 3) wreg(rt, buf.readBigUInt64LE(a));
        else if (size2 === 2) wreg(rt, buf.readUInt32LE(a));
        else if (size2 === 1) wreg(rt, buf.readUInt16LE(a));
        else wreg(rt, buf.readUInt8(a));
      } else {
        const val = rregZ(rt);
        if (size2 === 3) buf.writeBigUInt64LE(val & MASK64, a);
        else if (size2 === 2) buf.writeUInt32LE(Number(val & 0xffffffffn), a);
        else if (size2 === 1) buf.writeUInt16LE(Number(val & 0xffffn), a);
        else buf.writeUInt8(Number(val & 0xffn), a);
      }
      if (mode === 1) { wreg(rn, base + BigInt(immSigned)); } // post-index: writeback after access
      return true;
    }
    // register offset (bit21=1): LDR/STR Rt, [Rn, Rm{, extend}]
    if ((insn & 0x3b200c00) === 0x38200800) {
      const isLoad = (insn >>> 22) & 1;
      const rm = (insn >> 16) & 31;
      const opt = (insn >>> 13) & 7;
      const sBit = (insn >>> 12) & 1;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const sz = (insn >>> 30) & 3;
      let off = rregZ(rm);
      if (opt === 0) off = BigInt(Number(off) & 0xff);
      else if (opt === 1) off = BigInt(Number(off) & 0xffff);
      else if (opt === 2) off = BigInt(Number(off) & 0xffffffff);
      else if (opt === 4) off = BigInt((Number(off) & 0xff) | ((Number(off) & 0x80) ? 0xffffff00n : 0n));
      else if (opt === 5) off = BigInt((Number(off) & 0xffff) | ((Number(off) & 0x8000) ? 0xffff0000n : 0n));
      else if (opt === 6) off = BigInt(s32(off));
      // option 3/7 (UXTX/SXTX): full 64-bit
      const shift = sBit ? BigInt(sz) : 0n;
      off = (off << shift) & MASK64;
      const addr = Number((rreg(rn) + off) & MASK64);
      if (isLoad) {
        if (sz === 3) wreg(rt, buf.readBigUInt64LE(addr));
        else if (sz === 2) wreg(rt, buf.readUInt32LE(addr));
        else if (sz === 1) wreg(rt, buf.readUInt16LE(addr));
        else wreg(rt, buf.readUInt8(addr));
      } else {
        const val = rregZ(rt);
        if (sz === 3) buf.writeBigUInt64LE(val & MASK64, addr);
        else if (sz === 2) buf.writeUInt32LE(Number(val & 0xffffffffn), addr);
        else if (sz === 1) buf.writeUInt16LE(Number(val & 0xffffn), addr);
        else buf.writeUInt8(Number(val & 0xffn), addr);
      }
      return true;
    }
    // SIMD register offset (ldr q, [xn, xm])
    if ((insn & 0x3b200c00) === 0x3c200800) {
      const isLoad = (insn >>> 22) & 1;
      const rm = (insn >> 16) & 31;
      const opt = (insn >>> 13) & 7;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const scale = ((insn >>> 30) & 3) === 2 ? 16 : 8;
      const off = opt === 3 ? rreg(rm) : (rreg(rm) & 0xffffffffn);
      const addr = Number((rreg(rn) + off * BigInt(scale)) & MASK64);
      if (isLoad) vwrite(rt, buf.readBigUInt64LE(addr), buf.readBigUInt64LE(addr + 8));
      else { buf.writeBigUInt64LE(vregs[rt].lo, addr); buf.writeBigUInt64LE(vregs[rt].hi, addr + 8); }
      return true;
    }
    // SIMD unscaled/post/pre (LDR/STR q via f9/fc/ad/9c...)
    if ((insn >>> 24) === 0x3c || (insn >>> 24) === 0x2c) {
      const isLoad = (insn >>> 22) & 1;
      const bits = (insn >>> 23) & 3;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const imm9 = (insn >> 12) & 0x1ff;
      const immSigned = (imm9 << 23 >> 23);
      let base = rreg(rn);
      let addr = (base + BigInt(immSigned)) & MASK64;
      if (bits === 3 || bits === 1) { wreg(rn, addr); }
      const a = Number(addr);
      if (isLoad) vwrite(rt, buf.readBigUInt64LE(a), buf.readBigUInt64LE(a + 8));
      else { buf.writeBigUInt64LE(vregs[rt].lo, a); buf.writeBigUInt64LE(vregs[rt].hi, a + 8); }
      return true;
    }
    // LDR/STR SIMD unsigned offset (0xbd/0xfd/0x3d)
    if ((insn >>> 24) === 0xbd || (insn >>> 24) === 0xfd || (insn >>> 24) === 0x7d || (insn >>> 24) === 0x3d) {
      const isLoad = (insn >>> 22) & 1;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const imm12 = (insn >> 10) & 0xfff;
      const scale = ((insn >>> 30) & 3) === 2 ? 16 : 8;
      const a = Number(rreg(rn)) + imm12 * scale;
      if (isLoad) vwrite(rt, buf.readBigUInt64LE(a), buf.readBigUInt64LE(a + 8));
      else { buf.writeBigUInt64LE(vregs[rt].lo, a); buf.writeBigUInt64LE(vregs[rt].hi, a + 8); }
      return true;
    }
    // literal load (LDR x0, =...) 0x58? — 0x58xxxxxx
    if ((insn >>> 24) === 0x58) {
      const rt = insn & 31;
      const off = ((insn >> 5) & 0x7ffff) << 2;
      const offSigned = ((insn >> 23) & 1) ? ((off | 0x100000) - 0x200000) : off;
      const addr = pc + offSigned;
      wreg(rt, buf.readBigUInt64LE(addr));
      return true;
    }
    return false;
  }

  function handleSimd(insn) {
    const op = insn >>> 24;
    // --- Modified immediate (MOVI/MVNI/FMOV) + shift-by-immediate (SSHR/USHR/SSRA/SRI/SLI/SHLL) ---
    // Empirical layout, verified against LLVM disassembler test encodings:
    //   prefix bits 31:24 = 0 Q U 01111; tag "01" at bits 11:10
    //   immh = bits 22:19: 0 -> modified immediate, != 0 -> shift by immediate
    //   MOVI imm8 = abc(bits 18:16) : defgh(bits 9:5); cmode = bits 15:12; op bit29 (MVNI)
    //   shift imm = immh:immb at bits 22:16; esize = 8 << (31 - clz32(immh))
    if ((insn & 0xbf800000) === 0x0f000000 || (insn & 0xbf800000) === 0x2f000000) {
      const q = (insn >>> 30) & 1;
      const uBit = (insn >>> 29) & 1;
      const rd = insn & 31;
      const immh = (insn >>> 19) & 0xf;
      if (immh === 0) {
        const cmode = (insn >> 12) & 0xf;
        const imm8 = (((insn >>> 16) & 7) << 5) | ((insn >>> 5) & 0x1f);
        if (cmode === 0xf) {
          if (uBit) throw new Error('MOVI cmode f op1 pc=0x' + pc.toString(16));
          // FMOV (vector, immediate): a:b:cdefgh -> f32
          const a = (imm8 >>> 7) & 1, b = (imm8 >>> 6) & 1, cdef = imm8 & 0x3f;
          const f32 = ((a << 31) | ((b ^ 1) << 30) | (((b ? cdef : (~cdef & 0x3f)) << 24))) >>> 0;
          const v = BigInt(f32);
          const lo = v | (v << 32n);
          vwrite(rd, lo & MASK64, q ? lo & MASK64 : 0n);
          return true;
        }
        if (uBit && cmode === 0xe) {
          // MOVI bytemask (op=1, cmode 1110): imm8 bit k -> byte k = 0xff : 0x00, pattern repeated
          let v = 0n;
          for (let k = 0; k < 8; k++) if ((imm8 >>> k) & 1) v |= 0xffn << BigInt(k * 8);
          vwrite(rd, v & MASK64, (q ? v : 0n) & MASK64);
          return true;
        }
        let lane, bitsL;
        if ((cmode & 0xb) === 0) { lane = BigInt(imm8) << BigInt((cmode >> 1) * 8); bitsL = 32n; }
        else if (cmode === 0xc) { lane = (BigInt(imm8) << 8n) | 0xffn; bitsL = 32n; }
        else if (cmode === 0xd) { lane = (BigInt(imm8) << 16n) | 0xffffn; bitsL = 32n; }
        else if (cmode === 0xe) { const b8 = BigInt(imm8); lane = b8 | (b8 << 8n) | (b8 << 16n) | (b8 << 24n); bitsL = 32n; }
        else if (cmode === 8) { lane = BigInt(imm8); bitsL = 16n; }
        else if (cmode === 9) { lane = BigInt(imm8) | 0xff00n; bitsL = 16n; }
        else if (cmode === 0xa) { lane = BigInt(imm8) << 8n; bitsL = 16n; }
        else if (cmode === 0xb) { lane = (BigInt(imm8) << 8n) | 0xffn; bitsL = 16n; }
        else throw new Error('MOVI cmode 0x' + cmode.toString(16) + ' pc=0x' + pc.toString(16));
        if (uBit) {
          if (cmode > 0xa) throw new Error('MVNI cmode 0x' + cmode.toString(16) + ' pc=0x' + pc.toString(16));
          lane = ~lane & ((1n << bitsL) - 1n);
        }
        const maskL = (1n << bitsL) - 1n;
        const lanesN = Number((q ? 128n : 64n) / bitsL);
        let lo = 0n, hi = 0n;
        for (let i = 0; i < lanesN; i++) {
          const sh = BigInt(i) * bitsL;
          if (sh < 64n) lo |= (lane & maskL) << sh;
          else hi |= (lane & maskL) << (sh - 64n);
        }
        vwrite(rd, lo & MASK64, hi & MASK64);
        return true;
      }
      const immb = (insn >>> 16) & 7;
      const imm = (immh << 3) | immb;
      const esize = 8 << (31 - Math.clz32(immh));
      const opcode = (insn >> 11) & 0x1f;
      const rn = (insn >> 5) & 31;
      const bitsL = BigInt(esize);
      const maskL = (1n << bitsL) - 1n;
      const lanesN = (q ? 128 : 64) / esize;
      if (opcode === 0 || opcode === 2) { // SSHR/USHR (0), SSRA/USRA (2)
        const shift = esize - (imm % esize);
        let lo = 0n, hi = 0n;
        for (let i = 0; i < lanesN; i++) {
          const sh = BigInt(i) * bitsL;
          let src = sh < 64n ? (vregs[rn].lo >> sh) & maskL : (vregs[rn].hi >> (sh - 64n)) & maskL;
          if (!uBit) {
            if ((src >> BigInt(esize - 1)) & 1n) src |= ~maskL;
            src = BigInt.asIntN(64, src) >> BigInt(shift);
          } else {
            src = src >> BigInt(shift);
          }
          let v = src & maskL;
          if (opcode === 2) {
            const old = sh < 64n ? (vregs[rd].lo >> sh) & maskL : (vregs[rd].hi >> (sh - 64n)) & maskL;
            v = (old + v) & maskL;
          }
          if (sh < 64n) lo |= v << sh; else hi |= v << (sh - 64n);
        }
        vwrite(rd, lo & MASK64, hi & MASK64);
        return true;
      }
      if (opcode === 8 || opcode === 10) { // SRI (8), SLI (10)
        const shift = opcode === 8 ? esize - (imm % esize) : immb;
        let lo = 0n, hi = 0n;
        for (let i = 0; i < lanesN; i++) {
          const sh = BigInt(i) * bitsL;
          const old = sh < 64n ? (vregs[rd].lo >> sh) & maskL : (vregs[rd].hi >> (sh - 64n)) & maskL;
          const src = sh < 64n ? (vregs[rn].lo >> sh) & maskL : (vregs[rn].hi >> (sh - 64n)) & maskL;
          let v, keep;
          if (opcode === 8) { v = src >> BigInt(shift); keep = maskL >> BigInt(shift); }
          else { v = (src << BigInt(shift)) & maskL; keep = (maskL << BigInt(shift)) & maskL; }
          const res = (old & ~keep) | (v & keep);
          if (sh < 64n) lo |= res << sh; else hi |= res << (sh - 64n);
        }
        vwrite(rd, lo & MASK64, hi & MASK64);
        return true;
      }
      if (opcode === 20) { // SSHLL/USHLL (10100) — widen source lanes to double-width dest lanes
        const shift = immb;
        const dBits = BigInt(esize * 2);
        const dMask = (1n << dBits) - 1n;
        const nSrc = 64 / esize; // 64 bits worth of source lanes
        const startLane = q ? nSrc : 0; // Q=1 -> upper half of the source register
        let dLo = 0n, dHi = 0n;
        for (let i = 0; i < nSrc; i++) {
          const laneIdx = startLane + i;
          const sh = BigInt(laneIdx) * bitsL;
          let src = sh < 64n ? (vregs[rn].lo >> sh) & maskL : (vregs[rn].hi >> (sh - 64n)) & maskL;
          if (!uBit) {
            if ((src >> BigInt(esize - 1)) & 1n) src |= ~maskL;
            src = BigInt.asIntN(64, src);
          }
          const v = (src << BigInt(shift)) & dMask;
          const dsh = BigInt(i) * dBits;
          if (dsh < 64n) dLo |= v << dsh; else dHi |= v << (dsh - 64n);
        }
        vwrite(rd, dLo & MASK64, dHi & MASK64);
        return true;
      }
      throw new Error('vec shift op ' + opcode + ' pc=0x' + pc.toString(16) + ' insn=0x' + insn.toString(16));
    }
    // three-same SIMD (prefix bits 27:24 = 1110, bit10 = 1).
    // Logical family: opcode(15:11) == 00011; op selected by U(bit29) + bits(23:22):
    //   U=0: 00 AND, 01 BIC, 10 ORR, 11 ORN | U=1: 00 EOR, 01 BSL, 10 BIT, 11 BIF
    // Integer: opcode 10000 = ADD(U=0)/SUB(U=1), 10011 = MUL — lane-wise by size(23:22).
    if (((insn >>> 24) & 0x0f) === 0x0e && ((insn >>> 10) & 1) === 1) {
      const q = (insn >>> 30) & 1;
      const u = (insn >>> 29) & 1;
      const size2 = (insn >>> 22) & 3;
      const opcode = (insn >> 11) & 0x1f;
      const rm = (insn >> 16) & 31, rn = (insn >> 5) & 31, rd = insn & 31;
      const fixQ = (lo, hi) => vwrite(rd, BigInt(lo) & MASK64, q ? BigInt(hi) & MASK64 : 0n);
      if (opcode === 3 && ((insn >>> 21) & 1) === 1) { // logical family (b21 fixed = 1)
        const k = (u << 2) | size2;
        const A = vregs[rn], B = vregs[rm], D = vregs[rd];
        let lo, hi;
        if (k === 0) { lo = A.lo & B.lo; hi = A.hi & B.hi; }                     // AND
        else if (k === 1) { lo = A.lo & ~B.lo; hi = A.hi & ~B.hi; }              // BIC
        else if (k === 2) { lo = A.lo | B.lo; hi = A.hi | B.hi; }                // ORR
        else if (k === 3) { lo = A.lo | ~B.lo; hi = A.hi | ~B.hi; }              // ORN
        else if (k === 4) { lo = A.lo ^ B.lo; hi = A.hi ^ B.hi; }                // EOR
        else if (k === 5) { lo = (D.lo & (A.lo ^ B.lo)) ^ B.lo; hi = (D.hi & (A.hi ^ B.hi)) ^ B.hi; } // BSL
        else if (k === 6) { lo = (A.lo & B.lo) | (D.lo & ~B.lo); hi = (A.hi & B.hi) | (D.hi & ~B.hi); } // BIT
        else { lo = (A.lo & ~B.lo) | (D.lo & B.lo); hi = (A.hi & ~B.hi) | (D.hi & B.hi); }             // BIF
        fixQ(lo, hi);
        return true;
      }
      if (opcode === 6 || opcode === 7) { // CMGT/CMHI (00110), CMGE/CMHS (00111)
        const bitsL = size2 === 0 ? 8n : size2 === 1 ? 16n : size2 === 2 ? 32n : 64n;
        const maskL = (1n << bitsL) - 1n;
        const lanes = 64 / Number(bitsL);
        const cmpLane = (a, b) => {
          if (u) return a > b || (opcode === 7 && a === b);
          const half = 1n << (bitsL - 1n);
          const sa = a >= half ? a - (maskL + 1n) : a;
          const sb = b >= half ? b - (maskL + 1n) : b;
          return opcode === 6 ? sa > sb : sa >= sb;
        };
        let lo = 0n, hi = 0n;
        for (let i = 0; i < lanes; i++) {
          const sh = BigInt(i) * bitsL;
          if (cmpLane((vregs[rn].lo >> sh) & maskL, (vregs[rm].lo >> sh) & maskL)) lo |= maskL << sh;
          if (cmpLane((vregs[rn].hi >> sh) & maskL, (vregs[rm].hi >> sh) & maskL)) hi |= maskL << sh;
        }
        fixQ(lo, hi);
        return true;
      }
      if (opcode === 16 || opcode === 19) { // 16: ADD/SUB, 19: MUL
        const bitsL = size2 === 0 ? 8n : size2 === 1 ? 16n : size2 === 2 ? 32n : 64n;
        const maskL = (1n << bitsL) - 1n;
        const lanes = 64 / Number(bitsL); // lanes per 64-bit half
        let lo = 0n, hi = 0n;
        for (let i = 0; i < lanes; i++) {
          const sh = BigInt(i) * bitsL;
          const a = (vregs[rn].lo >> sh) & maskL;
          const b = (vregs[rm].lo >> sh) & maskL;
          const v = opcode === 19 ? a * b : (u ? a - b : a + b);
          lo |= (v & maskL) << sh;
          const a2 = (vregs[rn].hi >> sh) & maskL;
          const b2 = (vregs[rm].hi >> sh) & maskL;
          const v2 = opcode === 19 ? a2 * b2 : (u ? a2 - b2 : a2 + b2);
          hi |= (v2 & maskL) << sh;
        }
        fixQ(lo, hi);
        return true;
      }
      throw new Error('vec3 opcode ' + opcode + ' pc=0x' + pc.toString(16) + ' insn=0x' + insn.toString(16));
    }
    // SHLL/SHLL2 (prefix 0x2E/0x6E, bit16=1, bits 15:10 = 001110; selector bits 23:21 = 1/3/5 → 8/16/32-bit source).
    // Ground truth: shll2 v6.4s, v8.8h, #16 = 0x6E613906; shll2 v2.8h, v4.16b, #8 = 0x6E213882.
    // Shift each source lane left by its own width into a double-width destination lane.
    if (((insn >>> 24) === 0x2e || (insn >>> 24) === 0x6e) && ((insn >>> 16) & 1) === 1 && ((insn >>> 10) & 0x3f) === 0x0e) {
      const q = (insn >>> 30) & 1;
      const sel = (insn >>> 21) & 7;
      const srcBits = sel === 1 ? 8n : sel === 3 ? 16n : 32n;
      const rn = (insn >> 5) & 31, rd = insn & 31;
      const srcMask = (1n << srcBits) - 1n;
      const nSrc = Number(64n / srcBits); // lanes in the used half of Vn
      const start = q ? nSrc : 0;          // SHLL2 -> upper half of the source
      const dBits = srcBits * 2n;
      let lo = 0n, hi = 0n;
      for (let i = 0; i < nSrc; i++) {
        const sh = BigInt(start + i) * srcBits;
        const v = (sh < 64n ? (vregs[rn].lo >> sh) : (vregs[rn].hi >> (sh - 64n))) & srcMask;
        const val = v << srcBits; // shift-left-long by the source lane width
        const dsh = BigInt(i) * dBits;
        if (dsh < 64n) lo |= val << dsh; else hi |= val << (dsh - 64n);
      }
      vwrite(rd, lo & MASK64, hi & MASK64);
      return true;
    }
    // modified immediate + shift-by-immediate families are fully handled by the
    // combined handler at the top of handleSimd (prefix 0x0F/0x2F/0x4F/0x6F, tag 01)
    // SIMD load/store multiple structures (LD1/ST1/...) — 0x0C/0x4C
    if ((insn >>> 24) === 0x0c || (insn >>> 24) === 0x4c) {
      const isLoad = ((insn >>> 22) & 1) === 1;
      const bits2123 = (insn >>> 21) & 7;
      const opcode = (insn >>> 23) & 3; // 00 ST4/LD4, 01 ST1x4/LD1x4, 10 ST3/LD3, 11 ST1x1/LD1x1
      const q = (insn >>> 30) & 1;
      const size2 = (insn >>> 10) & 3;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const regCount = opcode === 0 ? 4 : opcode === 1 ? 4 : opcode === 2 ? 3 : 1;
      const bytesPerReg = q ? 16 : 8;
      const post = bits2123 === 3 || ((insn >>> 23) & 7) === 3;
      let base = rreg(rn);
      const postImm = ((insn >> 16) & 0x1f) || (regCount * bytesPerReg);
      const addr = Number(base);
      for (let r = 0; r < regCount; r++) {
        const a = addr + r * bytesPerReg;
        if (isLoad) vwrite(rt + r, buf.readBigUInt64LE(a), buf.readBigUInt64LE(a + 8));
        else { buf.writeBigUInt64LE(vregs[rt + r].lo, a); buf.writeBigUInt64LE(vregs[rt + r].hi, a + 8); }
      }
      if (post) wreg(rn, base + BigInt(regCount * bytesPerReg));
      return true;
    }
    // SIMD load/store single structure — 0x0D/0x4D handled partially by ld/st groups
    if ((insn >>> 24) === 0x0d || (insn >>> 24) === 0x4d) {
      const isLoad = ((insn >>> 22) & 1) === 1;
      const opcode = (insn >>> 23) & 3;
      const size2 = (insn >>> 10) & 3;
      const q = (insn >>> 30) & 1;
      const rn = (insn >> 5) & 31, rt = insn & 31;
      const post = ((insn >>> 23) & 7) === 1;
      let base = rreg(rn);
      const addr = Number(base);
      const total = q ? 16 : 8;
      // LD1 single: opcode 11 (ST1), index from size:Q:S bits
      const s = (insn >> 12) & 1;
      if (size2 === 0) {
        const idx = (q ? 16 : 8) * 0 + s + ((insn >>> 14) & 1) * 2 + ((insn >>> 16) & 1) * 4;
        const byteIdx = ((insn >>> 16) & 1) * 8 + ((insn >>> 14) & 1) * 4 + ((insn >>> 12) & 1) * 2 + ((insn >>> 10) & 1) * 1 + s * 0;
        const off = ((insn >>> 14) & 1) * 2 + ((insn >>> 10) & 1) + ((insn >>> 12) & 1) * 0;
      }
      // Simplified: treat as LD1/ST1 8-bit single with index from S:size
      const index = ((insn >>> 14) & 1) * 2 + s + ((insn >>> 10) & 3) * 0;
      const esize = size2 === 3 ? 8 : size2 === 2 ? 4 : size2 === 1 ? 2 : 1;
      const bytes = esize;
      if (isLoad) {
        const val = buf.readUIntLE ? 0 : 0;
        let v = 0n;
        for (let i = 0; i < bytes; i++) v |= BigInt(buf[addr + i]) << BigInt(i * 8);
        // place into lane index of rt
        const laneOff = BigInt((q ? 16 : 8) === 16 ? 8 : 0);
        // put at byte offset = index*esize... simplified: put in low or high half
        if (index < (q ? 16 : 8) / esize / 2 || !q) {
          const shift = BigInt(index * esize);
          if (shift < 64n) vregs[rt].lo |= v << shift;
          else vregs[rt].hi |= v << (shift - 64n);
        }
      } else {
        let v;
        const shift = BigInt(index * esize);
        if (shift < 64n) v = (vregs[rt].lo >> shift) & ((1n << BigInt(esize * 8)) - 1n);
        else v = (vregs[rt].hi >> (shift - 64n)) & ((1n << BigInt(esize * 8)) - 1n);
        for (let i = 0; i < bytes; i++) buf[addr + i] = Number((v >> BigInt(i * 8)) & 0xffn);
      }
      if (post) wreg(rn, base + BigInt(bytes));
      return true;
    }
    // DUP / INS — 0x0E family scalar copy
    if ((insn >>> 24) === 0x0e || (insn >>> 24) === 0x4e) {
      const opcode = (insn >> 17) & 0xf;
      const imm5 = (insn >> 16) & 0x1f;
      const rn = (insn >> 5) & 31, rd = insn & 31;
      if (opcode === 0) {
        // DUP general: copy register rn into all lanes
        if (imm5 === 1) { const v = rreg(rn) & 0xffn; let lo = 0n; for (let i = 0; i < 16; i++) lo |= v << BigInt(i * 8); vwrite(rd, lo, lo); return true; }
        if (imm5 === 2) { const v = rreg(rn) & 0xffffn; let lo = 0n; for (let i = 0; i < 8; i++) lo |= v << BigInt(i * 16); vwrite(rd, lo, 0n); return true; }
        if (imm5 === 4) { const v = rreg(rn) & 0xffffffffn; let lo = 0n; for (let i = 0; i < 4; i++) lo |= v << BigInt(i * 32); vwrite(rd, lo, 0n); return true; }
        if (imm5 === 8) { const v = rreg(rn) & MASK64; vwrite(rd, v, v); return true; }
        // DUP element (vector): imm5 >= 16?
        const size2 = 31 - Math.clz32(imm5);
        if (size2 >= 0 && imm5 > 0) {
          const index = imm5 & ((1 << size2) - 1);
          const esize = 1 << size2;
          const src = (index * esize) < 64 ? ((vregs[rn].lo >> BigInt(index * esize)) & BigInt((1 << esize * 8) - 1)) : ((vregs[rn].hi >> BigInt(index * esize - 64)) & BigInt((1 << esize * 8) - 1));
          const lanes = 128 / (esize * 8);
          let lo = 0n, hi = 0n;
          for (let i = 0; i < lanes; i++) { const sh = BigInt(i * esize * 8); if (sh < 64n) lo |= src << sh; else hi |= src << (sh - 64n); }
          vwrite(rd, lo, hi);
          return true;
        }
      }
      if (opcode === 5) { // INS (MOV element, general)
        // imm5 encodes size+index
        const size2 = 31 - Math.clz32(imm5);
        const index = imm5 & ((1 << size2) - 1);
        const esize = 1 << size2;
        const v = rreg(rn) & BigInt((1n << BigInt(esize * 8)) - 1n);
        const sh = BigInt(index * esize * 8);
        let lo = vregs[rd].lo, hi = vregs[rd].hi;
        const mask = BigInt((1 << esize * 8) - 1);
        if (sh < 64n) lo = (lo & ~(mask << sh)) | ((v & mask) << sh);
        else hi = (hi & ~(mask << (sh - 64n))) | ((v & mask) << (sh - 64n));
        vwrite(rd, lo, hi);
        return true;
      }
      throw new Error('copy 0x0e opcode ' + opcode + ' pc=0x' + pc.toString(16) + ' insn=0x' + insn.toString(16));
    }
    // FMOV scalar? (0x1e...) unlikely
    return false;
  }

  function callMagic(target) {
    const t = BigInt(target);
    const fn = libcHandlers[t];
    if (fn) {
      const args = [regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7]];
      const r = fn(...args);
      regs[0] = (r === undefined ? 0n : BigInt(r)) & MASK64;
      return;
    }
    // not magic: real function pointer inside .so — just jump
    pc = Number(t);
  }

  function run(entry, args, stackSize = 0x100000) {
    exitResult = null; // a previous run's NewStringUTF must not terminate this one
    let lastSp = null;
    regs[31] = STACK_TOP;
    lastSp = regs[31];
    buf.writeBigUInt64LE(0n, Number(STACK_TOP) - 8); // return address 0 sentinel
    for (let i = 0; i < args.length && i < 8; i++) regs[i] = BigInt(args[i]) & MASK64;
    pc = entry;
    // return address 0 → when pc==0 stop
    let guard = 0;
    while (pc !== 0) {
      if (pc === 0) break;
      try { step(); } catch (e) {
        if (typeof e.message === 'string' && e.message.indexOf('pc=0x') < 0) throw new Error(e.message + ' at pc=0x' + pc.toString(16) + ' insn=0x' + rd32(pc).toString(16));
        throw e;
      }
      guard++;
      if (opts.watchSp) {
        const spNow = regs[31];
        if (spNow !== lastSp) {
          if (spNow < 0x700000n || spNow > 0x900000n) {
            (globalThis.__spWatch = globalThis.__spWatch || []).push({ pc: '0x' + (pc - 4).toString(16), insn: '0x' + rd32(pc - 4).toString(16), old: '0x' + lastSp.toString(16), sp: '0x' + spNow.toString(16) });
            if (globalThis.__spWatch.length > 10) throw new Error('SP left stack region, first at ' + globalThis.__spWatch[0].pc + ' insn ' + globalThis.__spWatch[0].insn + ' old=' + globalThis.__spWatch[0].old + ' new=' + globalThis.__spWatch[0].sp);
          }
          lastSp = spNow;
        }
      }
      if (exitResult !== null) break;
    }
    return { result: exitResult, regs: regs.map(String), steps };
  }

  return { run, buf, regs, getPC: () => pc };
}

module.exports = { createEmu };