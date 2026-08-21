// Golden-vector generator for the msgboard PoW.
//
// Transcribed from specs/04-msgboard-pow-v2.md ONLY. It does not import
// @msgboard/core and does not read the Rust: the point is a second,
// independent reading of the spec that the implementation can be checked
// against. If the two disagree, one of them misread the spec.
//
// secp256k1 is hand-rolled below for the same reason — and so this runs on a
// bare `node scripts/msgboard-pow-vector.js` with no install step.
//
// The digests it prints are pinned in `crates/net/msgboard-types/src/pow.rs`
// (mod `golden_vector`). The spec cites a `TestPoWGoldenVector` as the
// normative worked example; no such test exists upstream, so this is it.

const crypto = require('crypto')

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n

const mod = (a, m = P) => ((a % m) + m) % m
const inv = (a, m = P) => {
  let [lo, hi] = [mod(a, m), m]
  let [x0, x1] = [1n, 0n]
  while (lo > 1n) { const q = hi / lo; ;[lo, hi] = [hi - q * lo, lo]; [x0, x1] = [x1 - q * x0, x0] }
  return mod(x0, m)
}
// affine points as {x,y}; null is the point at infinity
const add = (p, q) => {
  if (!p) return q
  if (!q) return p
  if (p.x === q.x && mod(p.y + q.y) === 0n) return null
  const l = p.x === q.x && p.y === q.y
    ? mod(3n * p.x * p.x * inv(2n * p.y))
    : mod((q.y - p.y) * inv(q.x - p.x))
  const x = mod(l * l - p.x - q.x)
  return { x, y: mod(l * (p.x - x) - p.y) }
}
const mul = (k, p = { x: GX, y: GY }) => {
  let r = null, a = p
  while (k > 0n) { if (k & 1n) r = add(r, a); a = add(a, a); k >>= 1n }
  return r
}
const compress = (pt) => {
  const px = pt.x.toString(16).padStart(64, '0')
  return Buffer.from(((pt.y & 1n) === 0n ? '02' : '03') + px, 'hex')
}

const sha256 = (b) => crypto.createHash('sha256').update(b).digest()
const hex = (b) => '0x' + Buffer.from(b).toString('hex')
const be = (v, size) => {
  const b = Buffer.alloc(size); let n = BigInt(v)
  for (let i = size - 1; i >= 0; i--) { b[i] = Number(n & 0xffn); n >>= 8n }
  return b
}

const difficulty = (m, d, len) => ((2n ** 24n + BigInt(len) * 10_000n) * BigInt(m)) / BigInt(d)
const powTarget = (d) => 2n ** 256n / d

const payloadHash = (m) => sha256(Buffer.concat([
  Buffer.from(m.category.slice(2), 'hex'),
  Buffer.from(m.data.slice(2), 'hex'),
]))

const scalarHash = (m, ph) => sha256(Buffer.concat([
  be(m.version, 1),
  Buffer.from(m.blockHash.slice(2), 'hex'),
  ph,
  be(m.workMultiplier, 8),
  be(m.workDivisor, 8),
  be(m.nonce, 8),
]))

function steps(m) {
  const ph = payloadHash(m)
  const sh = scalarHash(m, ph)
  const scalar = BigInt(hex(sh))
  if (scalar === 0n || scalar >= N) return { ph, sh, rejected: true }
  const pt = mul(scalar)
  if (!pt) return { ph, sh, rejected: true }
  const compressed = compress(pt)
  return { ph, sh, compressed, workHash: sha256(compressed) }
}

// Sanity: G*1 must be the published generator, compressed.
const g1 = compress(mul(1n))
if (hex(g1) !== '0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
  throw new Error('secp256k1 self-check failed: ' + hex(g1))

const A = {
  version: 1,
  blockHash: '0x3a2ca760216c5cb648c32aab73cbc1cdfdbcf02f77a4cd190995e3c46f3932b5',
  category: '0x6368617474657200000000000000000000000000000000000000000000000000',
  data: '0x' + Buffer.from('golden vector', 'utf8').toString('hex'),
  nonce: 1, workMultiplier: 10_000, workDivisor: 1_000_000,
}
const len = (A.data.length - 2) / 2
const a = steps(A), aD = difficulty(A.workMultiplier, A.workDivisor, len)
console.log('=== VECTOR A (version 1, nonce 1, unmined) ===')
console.log('difficulty D    ', aD.toString())
console.log('target          ', '0x' + powTarget(aD).toString(16).padStart(64, '0'))
console.log('payloadHash     ', hex(a.ph))
console.log('scalarHash      ', hex(a.sh))
console.log('compressedPoint ', hex(a.compressed))
console.log('workHash        ', hex(a.workHash))
console.log('meetsDifficulty ', BigInt(hex(a.workHash)) < powTarget(aD))

const B = { ...A, workMultiplier: 1, workDivisor: 1_000 }
const bD = difficulty(B.workMultiplier, B.workDivisor, len), bT = powTarget(bD)
console.log('\n=== VECTOR B (version 1, nonce 57602) ===')
console.log('difficulty D    ', bD.toString())
for (const n of [57601, 57602, 57603]) {
  const s = steps({ ...B, nonce: n })
  console.log(`nonce ${n}`)
  console.log('  scalarHash     ', hex(s.sh))
  console.log('  compressedPoint', hex(s.compressed))
  console.log('  workHash       ', hex(s.workHash))
  console.log('  passes         ', BigInt(hex(s.workHash)) < bT)
}
