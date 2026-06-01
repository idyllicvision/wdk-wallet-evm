// Test-only shim for the `bare-buffer` module.
//
// In the Bare runtime, `bare-buffer` loads a native addon via `require.addon()`,
// which is not available under Node/Jest and throws
// "require.addon is not a function" at import time. For tests we only need a
// Buffer that behaves like Node's, so we re-export Node's Buffer.
//
// Authored as an ES module so Jest's experimental VM modules resolve the named
// `Buffer` export directly (matching `import { Buffer } from 'bare-buffer'`).

import { Buffer as NodeBuffer } from 'buffer'

export const Buffer = NodeBuffer

export default { Buffer: NodeBuffer }
