/**
 * CRX Parser Web Worker — Offloads .crx parsing to background thread.
 * Receives: ArrayBuffer (raw file bytes)
 * Returns: { zipArchiveBuffer: ArrayBuffer } or { error: string }
 */
import { parseCRX } from './crx-parser-core.js';

// Listen for messages from the main thread
self.onmessage = (event) => {
  try {
    const buffer = event.data;
    const view = new DataView(buffer);
    const result = parseCRX(view, buffer);

    if (result.error) {
      self.postMessage({ error: result.error });
    } else {
      self.postMessage({ zipArchiveBuffer: result.zip });
    }
  } catch (err) {
    self.postMessage({ error: 'Unexpected error while parsing: ' + err.message });
  }
};
