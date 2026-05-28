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
  recoverAddress
} from 'ethers'

import { Signer } from '@idyllicvision/bare-universal-signer'

/**
 * @typedef {Object} PrivateKeySignerEvmConfig
 * @property {import('@idyllicvision/bare-universal-signer').Signer} [bareSigner] - Pre-constructed Signer instance
 * @property {string} [rpcURL] - Optional RPC URL (ENS resolution only)
 * @property {Object} [keychainOpts={}] - Keychain opts forwarded to new Signer if bareSigner omitted
 */

/**
 * EVM signer backed by a raw private key stored in the iOS Keychain.
 * Compatible with ISignerEvm (wdk-wallet-evm). No HD derivation supported.
 */
export default class PrivateKeySignerEvm {
  /**
   * @param {PrivateKeySignerEvmConfig} [config={}]
   */
  constructor (config = {}) {
    this._bareSigner = config.bareSigner ||
      new Signer({ secretType: 'privateKey', autoLockMs: 30000, opts: config.keychainOpts || {} })
    this._address = undefined
    this._isActive = true
  }

  get isPrivateKey () { return true }
  get isActive () { return this._isActive }
  get index () { return 0 }
  get path () { return undefined }
  get address () { return this._address }

  /** @throws {Error} Always — private key signers cannot derive child accounts. */
  derive () {
    throw new Error('PrivateKeySignerEvm does not support derivation.')
  }

  /** @returns {Promise<string>} Checksummed Ethereum address */
  async getAddress () {
    if (!this._address) {
      const pubkey = await this._bareSigner.getPublicKey({ curve: 'secp256k1' })
      this._address = computeAddress('0x' + Buffer.from(pubkey).toString('hex'))
    }
    return this._address
  }

  /**
   * Sign a message (EIP-191).
   * @param {string} message
   * @returns {Promise<string>} 130-char lowercase hex (65 bytes: recovery||r||s)
   */
  async sign (message) {
    const messageHash = hashMessage(message)
    const hashBuffer = Buffer.from(messageHash.slice(2), 'hex')
    const sig = await this._bareSigner.sign({ curve: 'secp256k1', data: hashBuffer })
    return Buffer.from(sig).toString('hex')
  }

  /**
   * Sign a transaction.
   * @param {object} unsignedTx
   * @returns {Promise<string>} Serialized signed transaction hex
   */
  async signTransaction (unsignedTx) {
    const tx = copyRequest(unsignedTx)

    const { to, from } = await resolveProperties({
      to: tx.to ? resolveAddress(tx.to, this) : undefined,
      from: tx.from ? resolveAddress(tx.from, this) : undefined
    })

    if (to != null) tx.to = to
    if (from != null) tx.from = from

    if (tx.from != null) {
      const addr = await this.getAddress()
      assertArgument(
        getAddress(tx.from) === addr,
        'transaction from address mismatch',
        'tx.from',
        tx.from
      )
      delete tx.from
    }

    const btx = Transaction.from(tx)
    const txHashBuffer = Buffer.from(btx.unsignedHash.slice(2), 'hex')
    const expectedAddr = await this.getAddress()

    const sigBytes = await this._bareSigner.sign({ curve: 'secp256k1', data: txHashBuffer })

    if (sigBytes.length !== 65) {
      throw new Error(`Invalid signature length: ${sigBytes.length}, expected 65`)
    }

    const recovery = sigBytes[0]
    const r = '0x' + Buffer.from(sigBytes.slice(1, 33)).toString('hex')
    const s = '0x' + Buffer.from(sigBytes.slice(33, 65)).toString('hex')

    const sig = Signature.from({ r, s, yParity: recovery & 1 })
    const recoveredAddr = recoverAddress(btx.unsignedHash, sig)
    if (recoveredAddr.toLowerCase() !== expectedAddr.toLowerCase()) {
      throw new Error(`Signature verification failed: recovered ${recoveredAddr}, expected ${expectedAddr}`)
    }

    btx.signature = sig
    return btx.serialized
  }

  /**
   * EIP-712 typed data signing.
   * @param {object} domain
   * @param {object} types
   * @param {object} message
   * @returns {Promise<string>} Serialized signature
   */
  async signTypedData (domain, types, message) {
    const typedDataHash = TypedDataEncoder.hash(domain, types, message)
    const hashBuffer = Buffer.from(typedDataHash.slice(2), 'hex')
    const sigBytes = await this._bareSigner.sign({ curve: 'secp256k1', data: hashBuffer })
    const r = '0x' + Buffer.from(sigBytes.slice(1, 33)).toString('hex')
    const s = '0x' + Buffer.from(sigBytes.slice(33, 65)).toString('hex')
    return Signature.from({ r, s, yParity: sigBytes[0] & 1 }).serialized
  }

  dispose () { this._isActive = false }
}
