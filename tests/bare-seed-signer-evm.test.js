'use strict'

import { describe, expect, test } from '@jest/globals'

import {
  Transaction,
  TypedDataEncoder,
  hashMessage,
  verifyTypedData,
  recoverAddress
} from 'ethers'

import BareSeedSignerEvm from '../src/signers/bare-seed-signer-evm.js'
import {
  createMockBareSigner,
  parseRawSignatureHex
} from './helpers/mock-bare-signer.js'

// A second valid key (the EIP-155 example key) used to forge a signature from
// the "wrong" signer when exercising the recover-and-verify guard.
const OTHER_KEY =
  '0x4646464646464646464646464646464646464646464646464646464646464646'

const newSigner = (config = {}) =>
  new BareSeedSignerEvm({ bareSigner: createMockBareSigner(), ...config })

const baseTx = {
  to: '0x2222222222222222222222222222222222222222',
  value: 1_000_000_000_000_000n,
  nonce: 0,
  gasLimit: 21_000n,
  chainId: 1
}

describe('BareSeedSignerEvm', () => {
  test('rejects a malformed derivation path at construction', () => {
    expect(() => newSigner({ path: 'not/a/path' })).toThrow('Invalid path format')
  })

  test('derive() composes the BIP-44 path from a relative path', () => {
    const child = newSigner().derive("0'/0/3")
    expect(child.path).toBe("m/44'/60'/0'/0/3")
    expect(child.index).toBe(3)
    expect(() => newSigner().derive('0/0/')).toThrow('Invalid relative path format')
  })

  test('getAddress derives the checksummed address and caches it', async () => {
    const bare = createMockBareSigner()
    const signer = new BareSeedSignerEvm({ bareSigner: bare })

    expect(await signer.getAddress()).toBe(bare.address)
    expect(signer.address).toBe(bare.address) // getter populated after resolution
    await signer.getAddress()
    // Cached: the keychain (getPublicKey) is hit once, not per call — this
    // matters because each call can trigger a biometric prompt.
    expect(bare.calls.getPublicKey).toBe(1)
  })

  test('sign() returns the bare [recovery,r,s] layout and recovers to the signer (EIP-191)', async () => {
    const bare = createMockBareSigner()
    const signer = new BareSeedSignerEvm({ bareSigner: bare })

    const raw = await signer.sign('hello bare-seed')
    // Documents the (unprefixed, recovery-first) layout this method returns.
    expect(raw).toMatch(/^[0-9a-f]{130}$/)

    const { recovery, r, s } = parseRawSignatureHex(raw)
    const recovered = recoverAddress(hashMessage('hello bare-seed'), {
      r,
      s,
      yParity: recovery & 1
    })
    expect(recovered).toBe(bare.address)
  })

  // The 65-byte bare output is [recovery, r, s]; the signer must re-pack it into
  // ethers' {r, s, yParity}. This is the exact contract that broke in bug #1, so
  // we assert recovery across both EVM tx types (legacy RLP vs typed 1559).
  test.each([
    { label: 'EIP-1559 (type 2)', extra: { type: 2, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n } },
    { label: 'legacy (type 0)', extra: { type: 0, gasPrice: 3_000_000_000n } }
  ])('signTransaction $label recovers to the signer and binds chainId', async ({ extra }) => {
    const bare = createMockBareSigner()
    const signer = new BareSeedSignerEvm({ bareSigner: bare })
    await signer.getAddress()

    const parsed = Transaction.from(await signer.signTransaction({ ...baseTx, ...extra }))
    expect(parsed.from).toBe(bare.address) // recovery + byte order are correct
    expect(parsed.chainId).toBe(1n) // EIP-155 replay protection is in the signed payload
  })

  test('signTransaction throws when the returned signature is not the signer’s (recover-and-verify guard)', async () => {
    const real = createMockBareSigner()
    const other = createMockBareSigner(OTHER_KEY)
    // Address resolves from the real key, but signatures come from a different
    // key — the internal recoverAddress check must reject this.
    const mismatched = {
      getPublicKey: (...a) => real.getPublicKey(...a),
      sign: (...a) => other.sign(...a)
    }
    const signer = new BareSeedSignerEvm({ bareSigner: mismatched })
    await signer.getAddress()

    await expect(
      signer.signTransaction({ ...baseTx, type: 2, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n })
    ).rejects.toThrow('Signature verification failed')
  })

  test('signTransaction rejects a from-address that is not the signer', async () => {
    const signer = newSigner()
    await signer.getAddress()
    await expect(
      signer.signTransaction({ ...baseTx, type: 2, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, from: '0x1111111111111111111111111111111111111111' })
    ).rejects.toThrow('from address mismatch')
  })

  test('signTypedData (EIP-712) verifies for the signer — guards r/s/v byte order (#1)', async () => {
    const bare = createMockBareSigner()
    const signer = new BareSeedSignerEvm({ bareSigner: bare })

    const domain = { name: 'Test', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' }
    const types = { Mail: [{ name: 'from', type: 'address' }, { name: 'contents', type: 'string' }] }
    const value = { from: '0x1111111111111111111111111111111111111111', contents: 'hello' }

    const serialized = await signer.signTypedData(domain, types, value)
    expect(serialized).toMatch(/^0x[0-9a-fA-F]{130}$/)
    // verifyTypedData re-derives the digest and recovers — only passes if the
    // signer packed r/s/v correctly (the old raw-bytes path would not recover).
    expect(verifyTypedData(domain, types, value, serialized)).toBe(bare.address)
  })

  test('dispose() deactivates the signer and clears the cached address', () => {
    const signer = newSigner()
    signer.dispose()
    expect(signer.isActive).toBe(false)
    expect(signer.address).toBeUndefined()
  })
})
