'use strict';
// Extracts the signing certificate (DER bytes -> hex) from an APK.
// Handles v2/v3-only APKs (APK Signing Block, no META-INF/*.RSA).
const fs = require('fs');
const zlib = require('zlib');

function lp(buf, off) { // uint32-length-prefixed record
  const len = buf.readUInt32LE(off);
  return { data: buf.slice(off + 4, off + 4 + len), next: off + 4 + len };
}

function tryPairsFrom(buf, start, pairsEnd) {
  const out = [];
  let p = start;
  while (p < pairsEnd) {
    if (p + 8 > pairsEnd) return null;
    const plen = Number(buf.readBigUInt64LE(p));
    p += 8;
    if (plen < 4 || p + plen > pairsEnd) return null;
    out.push({ id: buf.readUInt32LE(p), value: buf.slice(p + 4, p + plen) });
    p += plen;
  }
  return p === pairsEnd ? out : null;
}

function parseSigningBlock(buf) {
  // scan every magic occurrence; for each, brute-force the pairs start
  // (some signers build blocks whose leading size field doesn't match AOSP's layout)
  let searchFrom = 0;
  while (true) {
    const magicIdx = buf.indexOf('APK Sig Block 42', searchFrom);
    if (magicIdx < 0) return [];
    searchFrom = magicIdx + 16;
    if (magicIdx < 260) continue;
    const pairsEnd = magicIdx - 8;
    const size2 = Number(buf.readBigUInt64LE(pairsEnd));
    const minStart = Math.max(0, pairsEnd - size2 - 64);
    for (let s = minStart; s <= pairsEnd; s += 4) {
      const pairs = tryPairsFrom(buf, s, pairsEnd);
      if (pairs && pairs.length) return pairs;
    }
  }
}

function certFromV2V3(blockValue) {
  // signers: u32-prefixed sequence of u32-prefixed signers
  const signersSeq = lp(blockValue, 0);
  const signer = lp(signersSeq.data, 0); // first signer
  const signedData = lp(signer.data, 0);
  const digests = lp(signedData.data, 0); // skip
  const certificates = lp(signedData.data, digests.next);
  const cert = lp(certificates.data, 0); // first certificate DER
  return cert.data;
}

function findLocalEntry(buf) {
  let off = 0;
  while (true) {
    const idx = buf.indexOf('PK\x03\x04', off);
    if (idx < 0) return null;
    const nlen = buf.readUInt16LE(idx + 26);
    const name = buf.slice(idx + 30, idx + 30 + nlen).toString('latin1');
    const method = buf.readUInt16LE(idx + 8);
    const csize = buf.readUInt32LE(idx + 18);
    const dataStart = idx + 30 + nlen + buf.readUInt16LE(idx + 28);
    if (/^META-INF\/.*\.RSA$/i.test(name)) {
      return method === 8 ? zlib.inflateRawSync(buf.slice(dataStart, dataStart + csize)) : buf.slice(dataStart, dataStart + csize);
    }
    off = dataStart + csize;
    if (off <= idx) off = idx + 4;
  }
}

function certFromV1(pk7) {
  // certificates are wrapped in SignedData's [0] IMPLICIT constructed field
  for (let i = 0; i < pk7.length - 4; i++) {
    if (pk7[i] === 0xa0 && (pk7[i + 1] === 0x82 || pk7[i + 1] === 0x83)) {
      const n = pk7[i + 1] & 0x7f;
      let hl = 2 + n;
      if (pk7[i + hl] === 0x30) {
        let certLen = pk7[i + hl + 1] & 0x7f;
        let certHl = 2;
        if (pk7[i + hl + 1] & 0x80) { certLen = 0; for (let k = 0; k < (pk7[i + hl + 1] & 0x7f); k++) certLen = certLen * 256 + pk7[i + hl + 2 + k]; certHl = 2 + (pk7[i + hl + 1] & 0x7f); }
        const start = i + hl;
        const der = pk7.slice(start, start + certHl + certLen);
        if (der.indexOf(Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d])) > 0) return der;
      }
    }
  }
  return null;
}

function getApkCertHex(apkPath) {
  const apk = Buffer.isBuffer(apkPath) ? apkPath : fs.readFileSync(apkPath);
  // v3 first (newest), then v2, then v1
  const pairs = parseSigningBlock(apk);
  for (const id of [0xf05368c0, 0x7109871a]) {
    const pair = pairs.find(p => p.id === id);
    if (pair) {
      try {
        const der = certFromV2V3(pair.value);
        if (der && der.length > 100) return der.toString('hex');
      } catch { /* try next scheme */ }
    }
  }
  const pk7 = findLocalEntry(apk);
  if (pk7) {
    const der = certFromV1(pk7);
    if (der) return der.toString('hex');
  }
  return null;
}

module.exports = { getApkCertHex };