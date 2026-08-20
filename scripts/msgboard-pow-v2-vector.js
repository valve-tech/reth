// Golden-vector generator for the NEW msgboard PoW construction.
//
// Transcribed from specs/04-msgboard-pow-v2.md ONLY. It deliberately does not
// import @msgboard/core or read the Rust: the whole point is to be a second,
// independent reading of the spec that the Rust implementation can be checked
// against. If the two disagree, one of them misread the spec.
//
// Run from the msgboard repo root so `elliptic` resolves.

const EC = require('elliptic').ec
const crypto = require('crypto')

const ec = new EC('secp256k1')
const g = ec.g
const N = BigInt('0x' + ec.curve.n.toString(16))

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest()
const hex = (buf) => '0x' + Buffer.from(buf).toString('hex')
const be = (value, size) => {
  const b = Buffer.alloc(size)
  let v = BigInt(value)
  for (let i = size - 1; i >= 0; i--) {
    b[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return b
}

// Step 2. D = ((2^24) + (10k * dataLen)) * workMultiplier / workDivisor
//         target = 2^256 / D
const difficulty = (m, d, dataLen) =>
  ((2n ** 24n + BigInt(dataLen) * 10_000n) * BigInt(m)) / BigInt(d)
const powTarget = (d) => 2n ** 256n / d

// Step 3. payloadHash = SHA256(category ‖ data)
const payloadHash = (msg) =>
  sha256(Buffer.concat([Buffer.from(msg.category.slice(2), 'hex'), Buffer.from(msg.data.slice(2), 'hex')]))

// Step 4. scalarHash = SHA256(version ‖ blockHash ‖ payloadHash ‖ M ‖ Div ‖ nonce)
//         1-byte version; 8-byte big-endian M, Div, nonce.
const scalarHash = (msg, payloadHashBytes) =>
  sha256(
    Buffer.concat([
      be(msg.version, 1),
      Buffer.from(msg.blockHash.slice(2), 'hex'),
      payloadHashBytes,
      be(msg.workMultiplier, 8),
      be(msg.workDivisor, 8),
      be(msg.nonce, 8),
    ]),
  )

// Step 5. scalar must satisfy 1 <= scalar < n — REJECT, do not reduce.
//         point = G*scalar, compressed (33 bytes), workHash = SHA256(compressed).
function steps(msg) {
  const ph = payloadHash(msg)
  const sh = scalarHash(msg, ph)
  const scalar = BigInt(hex(sh))
  if (scalar === 0n || scalar >= N) return { ph, sh, scalar, rejected: 'scalar out of range' }
  const point = g.mul(ec.keyFromPrivate(Buffer.from(sh)).getPrivate())
  if (point.isInfinity()) return { ph, sh, scalar, rejected: 'point at infinity' }
  const compressed = Buffer.from(point.encodeCompressed())
  const workHash = sha256(compressed)
  return { ph, sh, scalar, compressed, workHash }
}

// ── Vector A: construction only. Fixed nonce, no mining. ────────────────────
// Pins every intermediate digest regardless of whether the work is sufficient.
// This is the vector that catches a misread of the byte layout.
const A = {
  version: 1,
  blockHash: '0x3a2ca760216c5cb648c32aab73cbc1cdfdbcf02f77a4cd190995e3c46f3932b5',
  category: '0x6368617474657200000000000000000000000000000000000000000000000000',
  data: '0x' + Buffer.from('golden vector', 'utf8').toString('hex'),
  nonce: 1,
  workMultiplier: 10_000,
  workDivisor: 1_000_000,
}
const a = steps(A)
const aDataLen = (A.data.length - 2) / 2
const aD = difficulty(A.workMultiplier, A.workDivisor, aDataLen)

console.log('=== VECTOR A — construction, nonce fixed at 1, not mined ===')
console.log('version          ', A.version)
console.log('blockHash        ', A.blockHash)
console.log('category         ', A.category)
console.log('data             ', A.data, `(${aDataLen} bytes, "golden vector")`)
console.log('nonce            ', A.nonce)
console.log('workMultiplier   ', A.workMultiplier)
console.log('workDivisor      ', A.workDivisor)
console.log('--- derived ---')
console.log('difficulty D     ', aD.toString())
console.log('target           ', '0x' + powTarget(aD).toString(16).padStart(64, '0'))
console.log('payloadHash      ', hex(a.ph))
console.log('scalarHash       ', hex(a.sh))
console.log('scalar (dec)     ', a.scalar.toString())
console.log('compressedPoint  ', hex(a.compressed))
console.log('workHash         ', hex(a.workHash))
console.log('meetsDifficulty  ', BigInt(hex(a.workHash)) < powTarget(aD))

// ── Vector B: a mined message that actually satisfies the target. ───────────
const B = { ...A, workMultiplier: 1, workDivisor: 1_000 }
const bDataLen = (B.data.length - 2) / 2
const bD = difficulty(B.workMultiplier, B.workDivisor, bDataLen)
const bTarget = powTarget(bD)

let found = null
for (let nonce = 1; nonce <= 5_000_000; nonce++) {
  const s = steps({ ...B, nonce })
  if (s.rejected) continue
  if (BigInt(hex(s.workHash)) < bTarget) {
    found = { nonce, ...s }
    break
  }
}

console.log()
console.log('=== VECTOR B — mined, satisfies the target ===')
if (!found) {
  console.log('no nonce found in range')
} else {
  console.log('workMultiplier   ', B.workMultiplier)
  console.log('workDivisor      ', B.workDivisor)
  console.log('difficulty D     ', bD.toString())
  console.log('target           ', '0x' + bTarget.toString(16).padStart(64, '0'))
  console.log('nonce            ', found.nonce)
  console.log('payloadHash      ', hex(found.ph))
  console.log('scalarHash       ', hex(found.sh))
  console.log('compressedPoint  ', hex(found.compressed))
  console.log('workHash         ', hex(found.workHash))
  console.log('meetsDifficulty  ', BigInt(hex(found.workHash)) < bTarget)
}
