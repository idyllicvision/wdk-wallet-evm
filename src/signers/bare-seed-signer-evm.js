'use strict'

import { Buffer } from 'bare-buffer'
import {
  Signature,
  resolveProperties,
  resolveAddress,
  assertArgument,
  getAddress,
  Transaction,
  hashMessage,
  computeAddress,
  copyRequest,
  TypedDataEncoder,
  assert,
  JsonRpcProvider,
  recoverAddress
} from 'ethers'

import { getDefaultBareSigner } from '../bare-signer.js'

/**
 * @typedef {Object} EvmSignerConfig
 * @property {import('@idyllicvision/bare-universal-signer').Signer} [bareSigner] - Signer instance
 * @property {string} [path="m/44'/60'/0'/0/0"] - Derivation path
 * @property {string} [rpcURL] - RPC URL for ENS resolution
 * @property {Object} [keychainOpts={}] - Keychain options
 */

/**
 * EVM signer with EIP-191 and EIP-712 support.
 */
export default class BareSeedSignerEvm {
  /**
   * Create a new EVM signer.
   * @param {EvmSignerConfig} [config={}] - Configuration options
   */
  constructor (
    config = {
      bareSigner: undefined,
      path: "m/44'/60'/0'/0/0",
      rpcURL: undefined,
      keychainOpts: {}
    }
  ) {
    // Validate config
    if (config.path && !/^m(\/\d+'?)+$/.test(config.path)) {
      throw new Error('Invalid path format')
    }

    // Auto-initialize with default bare-signer if not provided
    this._bareSigner = config.bareSigner || getDefaultBareSigner()
    this._address = undefined
    this._path = config.path || "m/44'/60'/0'/0/0"
    this._isActive = true
    this._opts = config.keychainOpts || {}
    this._provider = undefined
    if (config.rpcURL) {
      this._provider = new JsonRpcProvider(config.rpcURL)
    }
  }

  /** @private @throws {Error} if the signer has been disposed. */
  _assertActive () {
    if (!this._isActive) {
      throw new Error('BareSeedSignerEvm: the signer has been disposed.')
    }
  }

  /**
   * Initialize the Ethereum address from the public key.
   * @private
   * @returns {Promise<string>}
   */
  async initializeAddress () {
    this._assertActive()
    if (this._address) {
      return this._address
    }
    const pubkey = await this.getPublicKey()
    const pubkeyHex = '0x' + Buffer.from(pubkey).toString('hex')
    const address = computeAddress(pubkeyHex)
    this._address = address
    return this._address
  }

  /**
   * Get the public key.
   * @returns {Promise<Uint8Array>}
   */
  async getPublicKey () {
    this._assertActive()
    const pubkey = await this._bareSigner.getPublicKey({
      path: this._path,
      curve: 'secp256k1',
      opts: this._opts
    })
    return pubkey
  }

  /** @returns {boolean} Whether the signer is active */
  get isActive () {
    return this._isActive
  }

  /** @returns {number|undefined} Last path component as number */
  get index () {
    if (!this._path) return undefined
    return +this._path.split('/').pop()
  }

  /** @returns {string} Current derivation path */
  get path () {
    return this._path
  }

  /** @returns {string|undefined} Ethereum address */
  get address () {
    return this._address
  }

  /**
   * Get the Ethereum address, initializing if needed.
   * @returns {Promise<string>}
   */
  async getAddress () {
    this._assertActive()
    if (!this._address) {
      await this.initializeAddress()
    }
    return this._address
  }

  /**
   * Derive a child signer from this signer.
   * @param {string} relPath - Relative derivation path (e.g., "0'/0/0")
   * @param {object} [_cfg] - Configuration options (ignored for EVM signers)
   * @returns {EvmSigner} A new child signer with the derived path
   */
  derive (relPath, _cfg) {
    this._assertActive()
    if (!relPath || typeof relPath !== 'string') {
      throw new Error('Invalid relative path: must be a non-empty string')
    }
    if (!/^(\d+'?\/)*\d+'?$/.test(relPath)) {
      throw new Error('Invalid relative path format: expected format like "0\'/0/0"')
    }

    // Construct full BIP-44 path: m/44'/60'/0'/0/0
    // relPath comes as "0'/0/0" (account/change/index)
    const fullPath = `m/44'/60'/${relPath}`

    const childSigner = new BareSeedSignerEvm({
      bareSigner: this._bareSigner,
      path: fullPath,
      keychainOpts: this._opts,
      rpcURL: this._provider?.url
    })
    childSigner._isRoot = false
    return childSigner
  }

  /**
   * Sign a message (EIP-191).
   *
   * NOTE: returns the raw bare-signer output as hex — `[recovery(1), r(32), s(32)]`
   * (recovery-first, no `0x` prefix). This is NOT a standard ethers signature
   * (`r‖s‖v`); do not pass it directly to ethers `verifyMessage`. Use
   * `signTypedData` / `signTransaction` for ethers-style serialized signatures.
   *
   * @param {string} message - Message to sign
   * @returns {Promise<string>} 130-char hex of `[recovery, r, s]`.
   */
  async sign (message) {
    this._assertActive()
    const messageHash = hashMessage(message)
    const hashBuffer = Buffer.from(messageHash.slice(2), 'hex')
    const sig = await this._bareSigner
      .sign({
        path: this._path,
        curve: 'secp256k1',
        data: hashBuffer,
        opts: this._opts
      })
      .then((sig) => Buffer.from(sig).toString('hex'))
    return sig
  }

  /**
   * Sign a transaction object and return its serialized form.
   * @param {object} unsignedTx - Transaction object
   * @returns {Promise<string>} Serialized signed transaction hex
   */
  async signTransaction (unsignedTx) {
    this._assertActive()
    const tx = copyRequest(unsignedTx)

    const { to, from } = await resolveProperties({
      to: tx.to ? resolveAddress(tx.to, this) : undefined,
      from: tx.from ? resolveAddress(tx.from, this) : undefined
    })

    if (to != null) {
      tx.to = to
    }
    if (from != null) {
      tx.from = from
    }

    if (tx.from != null) {
      assertArgument(
        getAddress(tx.from) === this.address,
        'transaction from address mismatch',
        'tx.from',
        tx.from
      )
      delete tx.from
    }

    const btx = Transaction.from(tx)
    const txHashHex = btx.unsignedHash
    const txHashBuffer = Buffer.from(txHashHex.slice(2), 'hex')

    const expectedAddr = await this.getAddress()
    const sigBytes = await this._bareSigner.sign({
      path: this._path,
      curve: 'secp256k1',
      data: txHashBuffer,
      opts: this._opts
    })

    // @noble/curves secp256k1.sign() with format: 'recovered' returns 65 bytes: [recovery(1), r(32), s(32)]
    if (sigBytes.length !== 65) {
      throw new Error(`Invalid signature length: ${sigBytes.length}, expected 65`)
    }

    // recovery is already the yParity bit (0 or 1) per @noble/curves v2 spec
    const recovery = sigBytes[0]
    const r = '0x' + Buffer.from(sigBytes.slice(1, 33)).toString('hex')
    const s = '0x' + Buffer.from(sigBytes.slice(33, 65)).toString('hex')

    const sig = Signature.from({ r, s, yParity: recovery & 1 })
    const recoveredAddr = recoverAddress(txHashHex, sig)
    if (recoveredAddr.toLowerCase() !== expectedAddr.toLowerCase()) {
      throw new Error(`Signature verification failed: recovered ${recoveredAddr}, expected ${expectedAddr}`)
    }

    btx.signature = sig
    return btx.serialized
  }

  /**
   * EIP-712 typed data signing.
   * @param {object} domain - Domain separator
   * @param {object} types - Type definitions
   * @param {object} message - Message to sign
   * @returns {Promise<string>} Serialized signature
   */
  async signTypedData (domain, types, message) {
    this._assertActive()
    const populated = await TypedDataEncoder.resolveNames(
      domain,
      types,
      message,
      async (name) => {
        assert(
          this._provider,
          'cannot resolve ENS names without a provider',
          'UNSUPPORTED_OPERATION',
          {
            operation: 'resolveName',
            info: { name }
          }
        )

        const address = await this._provider.resolveName(name)
        assert(address != null, 'unconfigured ENS name', 'UNCONFIGURED_NAME', {
          value: name
        })

        return address
      }
    )

    const typedDataHash = TypedDataEncoder.hash(populated.domain, types, populated.value)
    const hashBuffer = Buffer.from(typedDataHash.slice(2), 'hex')

    const sigBytes = await this._bareSigner.sign({
      path: this._path,
      curve: 'secp256k1',
      data: hashBuffer,
      opts: this._opts
    })

    // @noble/curves secp256k1.sign() with format: 'recovered' returns 65 bytes: [recovery(1), r(32), s(32)]
    if (sigBytes.length !== 65) {
      throw new Error(`Invalid signature length: ${sigBytes.length}, expected 65`)
    }

    // recovery is already the yParity bit (0 or 1) per @noble/curves v2 spec
    const recovery = sigBytes[0]
    const r = '0x' + Buffer.from(sigBytes.slice(1, 33)).toString('hex')
    const s = '0x' + Buffer.from(sigBytes.slice(33, 65)).toString('hex')

    const sig = Signature.from({ r, s, yParity: recovery & 1 })

    // Verify the signature recovers to this signer (parity with signTransaction),
    // so a wrong-key / malformed signature is never returned as valid.
    const expectedAddr = await this.getAddress()
    const recoveredAddr = recoverAddress(typedDataHash, sig)
    if (recoveredAddr.toLowerCase() !== expectedAddr.toLowerCase()) {
      throw new Error(`Signature verification failed: recovered ${recoveredAddr}, expected ${expectedAddr}`)
    }

    return sig.serialized
  }

  /**
   * Dispose of this signer and clear its cached state.
   *
   * Note: `_bareSigner` may be a shared singleton (see {@link getDefaultBareSigner}),
   * so we drop our reference to it rather than disposing it here. The owner of the
   * shared signer is responsible for its lifecycle.
   */
  dispose () {
    this._isActive = false
    this._address = undefined
    this._provider = undefined
    this._opts = {}
    this._bareSigner = undefined
  }
}
