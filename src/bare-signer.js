'use strict'

import { Signer } from '@idyllicvision/bare-universal-signer'

// Default Signers cached by a stable signature of their keychain opts. Keying by
// opts (instead of one process-wide singleton) prevents a later caller's keychain
// options from being silently ignored in favour of the first caller's, while
// still returning a stable instance for each distinct opts set.
const signers = new Map()

function optsKey (opts = {}) {
  return JSON.stringify(Object.entries(opts).sort())
}

/**
 * Get the default bare-signer instance for the given keychain options.
 * Each distinct `opts` set maps to its own 30s auto-lock Signer (created once).
 * @param {Object} [opts={}] - Keychain options.
 * @returns {Signer}
 */
export function getDefaultBareSigner (opts = {}) {
  const key = optsKey(opts)
  let signer = signers.get(key)
  if (!signer) {
    signer = new Signer({ autoLockMs: 30000, opts })
    signers.set(key, signer)
  }
  return signer
}

export * from '@idyllicvision/bare-universal-signer'
