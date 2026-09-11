'use strict';
// Minimal DEX parser: finds methods referencing given strings and dumps
// their const-string operands + invoke targets (enough to reconstruct
// header-building / native-call logic in the app's Java/Kotlin bytecode).
const fs = require('fs');
const zlib = require('zlib');
const path = require('path');

function unzipEntry(buf, wanted) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) { if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; } }
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28), extraLen = buf.readUInt16LE(off + 30), commentLen = buf.readUInt16LE(off + 32);
    const lfhOff = buf.readUInt32LE(off + 42);
    const name = buf.slice(off + 46, off + 46 + nameLen).toString();
    if (name === wanted) {
      const lNameLen = buf.readUInt16LE(lfhOff + 26), lExtraLen = buf.readUInt16LE(lfhOff + 28);
      const dataOff = lfhOff + 30 + lNameLen + lExtraLen;
      const raw = buf.slice(dataOff, dataOff + compSize);
      return method === 8 ? zlib.inflateRawSync(raw) : Buffer.from(raw);
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

function uleb(buf, off) { let result = 0, shift = 0; for (;;) { const b = buf[off++]; result |= (b & 0x7f) << shift; if (!(b & 0x80)) break; shift += 7; } return [result, off]; }

function parseDex(dex) {
  const stringIdsSize = dex.readUInt32LE(0x38), stringIdsOff = dex.readUInt32LE(0x3c);
  const typeIdsSize = dex.readUInt32LE(0x40), typeIdsOff = dex.readUInt32LE(0x44);
  const protoIdsSize = dex.readUInt32LE(0x48), protoIdsOff = dex.readUInt32LE(0x4c);
  const fieldIdsSize = dex.readUInt32LE(0x50), fieldIdsOff = dex.readUInt32LE(0x54);
  const methodIdsSize = dex.readUInt32LE(0x58), methodIdsOff = dex.readUInt32LE(0x5c);
  const classDefsSize = dex.readUInt32LE(0x60), classDefsOff = dex.readUInt32LE(0x64);

  const strings = new Array(stringIdsSize);
  for (let i = 0; i < stringIdsSize; i++) {
    const off = dex.readUInt32LE(stringIdsOff + i * 4);
    const [, p] = uleb(dex, off);
    let s = '';
    for (let j = p; dex[j] !== 0; j++) s += String.fromCharCode(dex[j]);
    strings[i] = s;
  }
  const typeDesc = (i) => strings[dex.readUInt32LE(typeIdsOff + i * 4)];
  const shortName = (d) => d.replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
  const methods = new Array(methodIdsSize);
  for (let i = 0; i < methodIdsSize; i++) {
    const base = methodIdsOff + i * 8;
    methods[i] = { class: shortName(typeDesc(dex.readUInt16LE(base))), name: strings[dex.readUInt32LE(base + 4)] };
  }
  const fields = new Array(fieldIdsSize);
  for (let i = 0; i < fieldIdsSize; i++) {
    const base = fieldIdsOff + i * 8;
    fields[i] = { class: shortName(typeDesc(dex.readUInt16LE(base))), name: strings[dex.readUInt32LE(base + 4)] };
  }
  // all methods with code
  const codeMethods = [];
  for (let c = 0; c < classDefsSize; c++) {
    const base = classDefsOff + c * 32;
    const cdOff = dex.readUInt32LE(base + 24);
    if (!cdOff) continue;
    let p = cdOff;
    const read = () => { const [v, np] = uleb(dex, p); p = np; return v; };
    const sf = read(), inf = read(), dm = read(), vm = read();
    let fidx = 0;
    for (let i = 0; i < sf; i++) { fidx += read(); read(); }
    for (let i = 0; i < inf; i++) { fidx += read(); read(); }
    let midx = 0;
    for (let i = 0; i < dm; i++) { midx += read(); read(); const codeOff = read(); if (codeOff) codeMethods.push({ method: methods[midx], codeOff }); }
    midx = 0;
    for (let i = 0; i < vm; i++) { midx += read(); read(); const codeOff = read(); if (codeOff) codeMethods.push({ method: methods[midx], codeOff }); }
  }
  return { dex, strings, methods, fields, codeMethods };
}

// decode a method's code: return list of {op, str?, target?, regs}
function decodeCode(D, codeOff) {
  const dex = D.dex;
  const insnsSize = dex.readUInt32LE(codeOff + 12);
  const insnsOff = codeOff + 16;
  const out = [];
  let pc = 0;
  while (pc < insnsSize) {
    const op = dex.readUInt16LE(insnsOff + pc * 2);
    const fmt = op & 0xff;
    const hi = op >> 8;
    if (fmt === 0x1a) { // const-string
      const strIdx = dex.readUInt16LE(insnsOff + (pc + 1) * 2);
      out.push({ op: 'const-string', str: D.strings[strIdx], reg: hi });
      pc += 2;
    } else if (fmt === 0x1b) { // const-string/jumbo
      const strIdx = dex.readUInt32LE(insnsOff + (pc + 1) * 2);
      out.push({ op: 'const-string', str: D.strings[strIdx], reg: hi });
      pc += 3;
    } else if ((fmt >= 0x6e && fmt <= 0x72) || (fmt >= 0x74 && fmt <= 0x78)) { // invoke
      const mIdx = dex.readUInt16LE(insnsOff + (pc + 1) * 2);
      out.push({ op: 'invoke', target: D.methods[mIdx].class + '.' + D.methods[mIdx].name });
      pc += 3;
    } else if (fmt === 0x60 || fmt === 0x62) { // sget-object / sput-object
      const fIdx = dex.readUInt16LE(insnsOff + (pc + 1) * 2);
      out.push({ op: fmt === 0x60 ? 'sget' : 'sput', target: D.fields[fIdx].class + '.' + D.fields[fIdx].name });
      pc += 2;
    } else if (fmt === 0x52 || fmt === 0x59) { // iget/iput
      const fIdx = dex.readUInt16LE(insnsOff + (pc + 1) * 2);
      out.push({ op: fmt === 0x52 ? 'iget' : 'iput', target: D.fields[fIdx].class + '.' + D.fields[fIdx].name });
      pc += 2;
    } else if (fmt === 0x0a) { out.push({ op: 'move-result' }); pc += 1; }
    else if (fmt === 0x12) { out.push({ op: 'const', v: hi }); pc += 1; }
    else if (fmt === 0x13) { out.push({ op: 'const/16', v: dex.readUInt16LE(insnsOff + (pc + 1) * 2) }); pc += 2; }
    else if (fmt === 0x14) { out.push({ op: 'const', v: dex.readUInt32LE(insnsOff + (pc + 1) * 2) }); pc += 3; }
    else if (fmt === 0x22 || fmt === 0x21 || fmt === 0x23) { pc += (fmt === 0x21) ? 2 : 3; } // new-instance etc (skip)
    else if (fmt === 0x00) { // nop / packed-switch payload
      pc += 1;
    } else {
      // conservative: use standard formats table for common sizes
      const sizes = { 0x01: 1, 0x02: 1, 0x03: 2, 0x04: 3, 0x05: 2, 0x06: 3, 0x07: 1, 0x08: 1, 0x09: 1, 0x0b: 1, 0x0c: 1, 0x0d: 1, 0x0e: 1, 0x0f: 1, 0x10: 1, 0x11: 1, 0x15: 2, 0x16: 2, 0x17: 1, 0x18: 5, 0x19: 2, 0x1c: 2, 0x1d: 1, 0x1e: 1, 0x1f: 2, 0x20: 2, 0x24: 3, 0x25: 4, 0x26: 5, 0x27: 3, 0x28: 4, 0x29: 5, 0x2a: 5, 0x2b: 1, 0x2c: 1, 0x2d: 1, 0x2e: 2, 0x2f: 1, 0x30: 2, 0x31: 1, 0x32: 2, 0x33: 1, 0x34: 3, 0x35: 3, 0x36: 3, 0x37: 3, 0x38: 3, 0x39: 4, 0x3a: 4, 0x3b: 4, 0x3c: 4, 0x3d: 5, 0x3e: 5, 0x3f: 2, 0x40: 4, 0x41: 4, 0x42: 4, 0x43: 5, 0x44: 5, 0x45: 5, 0x46: 5, 0x47: 1, 0x48: 2, 0x49: 3, 0x4a: 3, 0x4b: 3, 0x4c: 4, 0x4d: 5, 0x4e: 5, 0x4f: 5, 0x50: 2, 0x51: 2, 0x53: 2, 0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2, 0x58: 2, 0x5a: 2, 0x5b: 2, 0x5c: 2, 0x5d: 2, 0x5e: 2, 0x5f: 2, 0x61: 2, 0x63: 2, 0x64: 2, 0x65: 2, 0x66: 2, 0x67: 2, 0x68: 2, 0x69: 2, 0x6a: 2, 0x6b: 2, 0x6c: 2, 0x6d: 2, 0x73: 3, 0x79: 1, 0x7a: 1 };
      pc += sizes[fmt] || 2;
    }
  }
  return out;
}

function loadAppDex() {
  const APK = fs.readFileSync(path.join(process.cwd(), 'OscarTV.apk'));
  return parseDex(unzipEntry(APK, 'classes.dex'));
}

module.exports = { loadAppDex, decodeCode };