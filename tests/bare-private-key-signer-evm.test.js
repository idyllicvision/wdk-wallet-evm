'use strict'

import { describe, expect, test } from '@jest/globals'

import {
  Transaction,
  TypedDataEncoder,
  hashMessage,
  verifyTypedData,
  recoverAddress
} from 'ethers'

import BarePrivateKeySignerEvm from '../src/signers/bare-private-key-signer-evm.js'
import {
  createMockBareSigner,
  parseRawSignatureHex
} from './helpers/mock-bare-signer.js'

// A second valid key (the EIP-155 example key) for forging a wrong-signer sig.
const OTHER_KEY =
  '0x4646464646464646464646464646464646464646464646464646464646464646'

const newSigner = (config = {}) =>
  new BarePrivateKeySignerEvm({ bareSigner: createMockBareSigner(), ...config })

const domain = { name: 'Test', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' }
const types = { Mail: [{ name: 'from', type: 'address' }, { name: 'contents', type: 'string' }] }
const typedValue = { from: '0x1111111111111111111111111111111111111111', contents: 'hello' }

const baseTx = {
  to: '0x2222222222222222222222222222222222222222',
  value: 500_000_000_000_000n,
  nonce: 1,
  gasLimit: 21_000n,
  chainId: 1,
  type: 2,
  maxFeePerGas: 2_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n
}

// A bare signer whose address comes from key A but whose signatures come from
// key B — used to prove the recover-and-verify guards reject forged sigs.
const mismatchedBareSigner = () => {
  const real = createMockBareSigner()
  const other = createMockBareSigner(OTHER_KEY)
  return { getPublicKey: (...a) => real.getPublicKey(...a), sign: (...a) => other.sign(...a) }
}

describe('BarePrivateKeySignerEvm', () => {
  test('is a non-HD private-key signer that cannot derive', () => {
    const signer = newSigner()
    expect(signer.isPrivateKey).toBe(true)
    expect(signer.path).toBeUndefined()
    expect(() => signer.derive()).toThrow('does not support derivation')
  })

  test('getAddress derives the checksummed address and caches it', async () => {
    const bare = createMockBareSigner()
    const signer = new BarePrivateKeySignerEvm({ bareSigner: bare })
    expect(await signer.getAddress()).toBe(bare.address)
    await signer.getAddress()
    expect(bare.calls.getPublicKey).toBe(1) // cached; avoids repeat keychain hits
  })

  test('sign() returns the bare [recovery,r,s] layout and recovers to the signer (EIP-191)', async () => {
    const bare = createMockBareSigner()
    const signer = new BarePrivateKeySignerEvm({ bareSigner: bare })

    const raw = await signer.sign('hello pk signer')
    expect(raw).toMatch(/^[0-9a-f]{130}$/)

    const { recovery, r, s } = parseRawSignatureHex(raw)
    expect(recoverAddress(hashMessage('hello pk signer'), { r, s, yParity: recovery & 1 })).toBe(bare.address)
  })

  test('signTransaction (EIP-1559) recovers to the signer and binds chainId', async () => {
    const bare = createMockBareSigner()
    const signer = new BarePrivateKeySignerEvm({ bareSigner: bare })

    const parsed = Transaction.from(await signer.signTransaction(baseTx))
    expect(parsed.from).toBe(bare.address)
    expect(parsed.chainId).toBe(1n)
  })

  test('signTransaction rejects a from-address that is not the signer', async () => {
    await expect(
      newSigner().signTransaction({ ...baseTx, from: '0x1111111111111111111111111111111111111111' })
    ).rejects.toThrow('from address mismatch')
  })

  test('signTransaction throws when the returned signature is not the signer’s', async () => {
    const signer = new BarePrivateKeySignerEvm({ bareSigner: mismatchedBareSigner() })
    await expect(signer.signTransaction(baseTx)).rejects.toThrow('Signature verification failed')
  })

  test('signTypedData (EIP-712) verifies for the signer — guards r/s/v byte order', async () => {
    const bare = createMockBareSigner()
    const signer = new BarePrivateKeySignerEvm({ bareSigner: bare })

    const serialized = await signer.signTypedData(domain, types, typedValue)
    expect(serialized).toMatch(/^0x[0-9a-fA-F]{130}$/)
    expect(verifyTypedData(domain, types, typedValue, serialized)).toBe(bare.address)
  })

  test('signTypedData rejects a signature that does not recover to the signer (fix #1)', async () => {
    const signer = new BarePrivateKeySignerEvm({ bareSigner: mismatchedBareSigner() })
    await expect(signer.signTypedData(domain, types, typedValue)).rejects.toThrow(
      'Signature verification failed'
    )
  })

  test('dispose() deactivates the signer so further signing throws (fix #2)', async () => {
    const signer = newSigner()
    await signer.getAddress()
    signer.dispose()
    expect(signer.isActive).toBe(false)
    await expect(signer.sign('x')).rejects.toThrow('disposed')
    await expect(signer.signTransaction(baseTx)).rejects.toThrow('disposed')
  })

  test('dispose() drops the reference to the keychain signer and cached address', () => {
    const signer = newSigner()
    signer.dispose()
    expect(signer._bareSigner).toBeUndefined() // no lingering handle to the keychain signer
    expect(signer.address).toBeUndefined()
  })
})
