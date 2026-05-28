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
 * Interface for EVM signers.
 * @interface
 */
export class ISignerEvm {
  /**
   * True if the signer is currently active and usable.
   * @type {boolean}
   */
  get isActive () {
    throw new Error('isActive')
  }

  /**
   * The last component index for the derivation path of this signer.
   * @type {number|undefined}
   */
  get index () {
    throw new Error('index')
  }

  /**
   * The full derivation path if this is a child signer.
   * @type {string|undefined}
   */
  get path () {
    throw new Error('path')
  }

  /**
   * The Ethereum address.
   * @type {string|undefined}
   */
  get address () {
    throw new Error('address')
  }

  /**
   * Derive a child signer from this signer using a relative path.
   * @param {string} relPath - Relative derivation path
   * @param {object} [_cfg] - Configuration options
   * @returns {ISignerEvm}
   */
  derive (relPath, _cfg) {
    throw new Error('derive(relPath, cfg?)')
  }

  /**
   * Get the Ethereum address.
   * @returns {Promise<string>}
   */
  async getAddress () {
    throw new Error('getAddress(message)')
  }

  /**
   * Sign a plain message.
   * @param {string} message - Message to sign
   * @returns {Promise<string>}
   */
  async sign (message) {
    throw new Error('sign(message)')
  }

  /**
   * Sign a transaction object.
   * @param {object} unsignedTx - Transaction object
   * @returns {Promise<string>} Serialized signed transaction
   */
  async signTransaction (unsignedTx) {
    throw new Error('signTransaction(unsignedTx)')
  }

  /**
   * EIP-712 typed data signing.
   * @param {object} domain - Domain separator
   * @param {object} types - Type definitions
   * @param {object} message - Message to sign
   * @returns {Promise<string>}
   */
  async signTypedData (domain, types, message) {
    throw new Error('signTypedData(domain, types, message)')
  }

  /**
   * Clear any secret material from memory.
   */
  dispose () {
    throw new Error('dispose()')
  }
}

/**
 * EVM signer with EIP-191 and EIP-712 support.
 */
export default class EvmSigner {
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

  /**
   * Initialize the Ethereum address from the public key.
   * @private
   * @returns {Promise<string>}
   */
  async initializeAddress () {
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
    if (!relPath || typeof relPath !== 'string') {
      throw new Error('Invalid relative path: must be a non-empty string')
    }
    if (!/^(\d+'?\/)*\d+'?$/.test(relPath)) {
      throw new Error('Invalid relative path format: expected format like "0\'/0/0"')
    }

    // Construct full BIP-44 path: m/44'/60'/0'/0/0
    // relPath comes as "0'/0/0" (account/change/index)
    const fullPath = `m/44'/60'/${relPath}`

    const childSigner = new EvmSigner({
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
   * @param {string} message - Message to sign
   * @returns {Promise<string>} Hex-encoded signature
   */
  async sign (message) {
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
    const sig = await this._bareSigner
      .sign({
        path: this._path,
        curve: 'secp256k1',
        data: hashBuffer,
        opts: this._opts
      })
      .then((sig) => Signature.from(Buffer.from(sig).toString('hex')))

    return sig.serialized
  }

  /**
   * Dispose of this signer and mark it inactive.
   */
  dispose () {
    this._isActive = false
  }
}

export { EvmSigner }
