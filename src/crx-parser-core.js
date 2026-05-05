/**
 * CRX Parser Core — Shared parsing logic for both main thread and Web Worker.
 * Parses Chrome Extension .crx files (v2 & v3) and extracts the ZIP archive.
 */

/**
 * Format uint32 as zero-padded hex string (for debug/error messages).
 * @param {number} uint
 * @returns {string}
 */
export function formatUint32(uint) {
  return '0x' + uint.toString(16).padStart(8, '0');
}

/**
 * Parse a CRX file from a DataView.
 * Returns an object with the extracted ZIP buffer (and optionally public key
 * / signature for CRX v2), or an error object on failure.
 *
 * @param {DataView} dataView
 * @param {ArrayBuffer} arrayBuffer
 * @returns {{ zip: ArrayBuffer, publicKey?: ArrayBuffer, signature?: ArrayBuffer } | { error: string }}
 */
export function parseCRX(dataView, arrayBuffer) {
  // Minimum CRX file: magic (4) + version (4) + at least 4 bytes header = 12 bytes
  const MIN_CRX_SIZE = 12;
  if (arrayBuffer.byteLength < MIN_CRX_SIZE) {
    return { error: 'File is too small to be a valid CRX file (' + arrayBuffer.byteLength + ' bytes)' };
  }

  const magic = dataView.getUint32(0);

  if (magic !== 0x43723234) { // Cr24
    return { error: 'Invalid CRX file: magic number mismatch (got ' + formatUint32(magic) + ')' };
  }

  // Magic number is big-endian (ASCII "Cr24"), but version and all
  // subsequent numeric fields are little-endian per CRX specification.
  const version = dataView.getUint32(4, true);

  // ── CRX v2 format (with public key & signature headers) ─────────────────
  if (version === 2) {
    const publicKeyLength = dataView.getUint32(8, true);
    const signatureLength = dataView.getUint32(12, true);

    const headerEnd = 16 + publicKeyLength + signatureLength;

    if (headerEnd > arrayBuffer.byteLength) {
      return { error: 'Invalid CRX v2 file: headers exceed file size' };
    }

    const publicKey = arrayBuffer.slice(16, 16 + publicKeyLength);
    const signature = arrayBuffer.slice(16 + publicKeyLength, headerEnd);
    const zip = arrayBuffer.slice(headerEnd);

    return { zip, publicKey, signature };
  }

  // ── CRX v3 format (with protobuf-style header) ──────────────────────────
  if (version === 3) {
    const headerLength = dataView.getUint32(8, true);

    if (12 + headerLength > arrayBuffer.byteLength) {
      return { error: 'Invalid CRX v3 file: headers exceed file size' };
    }

    const zip = arrayBuffer.slice(12 + headerLength);
    return { zip };
  }

  return { error: 'Unsupported CRX version: ' + version + ' (only v2 and v3 are supported)' };
}
