/**
 * CRX File Parser — ES6 module
 * Parses Chrome Extension .crx files (v2 & v3) and extracts the ZIP archive.
 */
import { parseCRX } from './crx-parser-core.js';

export class CRXFileParser {
  /** @param {File} file */
  constructor(file) {
    this.file = file;
  }

  /**
   * Parse a CRX file from a DataView.
   * @param {DataView} dataView
   * @param {ArrayBuffer} arrayBuffer
   * @returns {[ArrayBuffer, ArrayBuffer|undefined, ArrayBuffer|undefined]|undefined}
   *   [zipArchiveBuffer, publicKeyBuffer, signatureBuffer]
   */
  parse(dataView, arrayBuffer) {
    const result = parseCRX(dataView, arrayBuffer);

    if (result.error) {
      console.error(result.error);
      return;
    }

    return [result.zip, result.publicKey, result.signature];
  }

  /**
   * Read the file and return a Promise that resolves with parse result.
   * @returns {Promise<[ArrayBuffer, ArrayBuffer?, ArrayBuffer?]|undefined>}
   */
  load() {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();

      reader.onload = (event) => {
        const buffer = event.target.result;
        const view = new DataView(buffer);
        resolve(this.parse(view, buffer));
      };

      reader.onerror = () => reject(new Error('Failed to read file'));

      reader.readAsArrayBuffer(this.file);
    });
  }
}
