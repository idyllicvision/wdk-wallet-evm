// Test-only shim for `@idyllicvision/bare-universal-signer`.
//
// The real package loads native Bare addons (bare-crypto, bare-type, ...) via
// `require.addon()` at import time, which is unavailable under Node/Jest. The
// EVM signer unit tests always inject their own mock bare signer, so the only
// thing tests need is a constructable `Signer` symbol. This stub throws if its
// signing primitives are actually invoked, so a test that forgets to inject a
// mock fails loudly rather than silently using a non-functional signer.
//
// Authored as an ES module so Jest's experimental VM modules resolve the named
// `Signer` export directly (matching `import { Signer } from '...'`).

export class Signer {
  constructor (opts = {}) {
    this._opts = opts
  }

  async getPublicKey () {
    throw new Error('bare-universal-signer shim: getPublicKey called; inject a mock bareSigner in tests')
  }

  async sign () {
    throw new Error('bare-universal-signer shim: sign called; inject a mock bareSigner in tests')
  }

  dispose () {}
}

export default { Signer }
