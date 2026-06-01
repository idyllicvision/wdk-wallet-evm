'use strict'

import { Buffer } from 'node:buffer'
import { SigningKey, computeAddress, getBytes } from 'ethers'

// A fixed test private key so the unit tests are deterministic.
export const TEST_PRIVATE_KEY =
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'

/**
 * Builds a mock `@idyllicvision/bare-universal-signer` backed by a real
 * secp256k1 key (via ethers' SigningKey). Signatures are genuine, so the EVM
 * signers' message / tx / typed-data outputs actually recover to the address.
 *
 * Shape matches what the EVM signers call:
 *   - `getPublicKey({ path?, curve, opts? })` → Uint8Array of the uncompressed key
 *   - `sign({ path?, curve, data })` → 65-byte `[recovery(1), r(32), s(32)]`
 *     (the byte layout @noble/curves produces with `format: 'recovered'`)
 *
 * @param {string} [privateKey] - 0x-prefixed 32-byte key (defaults to TEST_PRIVATE_KEY).
 */
export function createMockBareSigner (privateKey = TEST_PRIVATE_KEY) {
  const signingKey = new SigningKey(privateKey)
  const publicKey = signingKey.publicKey // 0x04… uncompressed
  const address = computeAddress(publicKey)

  return {
    publicKey,
    address,
    calls: { sign: 0, getPublicKey: 0 },
    async getPublicKey () {
      this.calls.getPublicKey++
      return getBytes(publicKey)
    },
    async sign ({ data }) {
      this.calls.sign++
      const digestHex = '0x' + Buffer.from(data).toString('hex')
      const sig = signingKey.sign(digestHex)
      const out = Buffer.alloc(65)
      out[0] = sig.yParity & 1
      Buffer.from(getBytes(sig.r)).copy(out, 1)
      Buffer.from(getBytes(sig.s)).copy(out, 33)
      return out
    }
  }
}

/**
 * Parses the `[recovery(1), r(32), s(32)]` hex string returned by the EVM
 * signers' `sign()` (EIP-191) back into an ethers-recoverable shape.
 *
 * @param {string} hex - 130-char hex string (no 0x prefix).
 */
export function parseRawSignatureHex (hex) {
  const buf = Buffer.from(hex, 'hex')
  return {
    recovery: buf[0],
    r: '0x' + buf.subarray(1, 33).toString('hex'),
    s: '0x' + buf.subarray(33, 65).toString('hex')
  }
}
