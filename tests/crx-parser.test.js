import { describe, it, expect } from 'vitest';
import { CRXFileParser } from '../src/crx-parser.js';

/**
 * Build a minimal valid CRX v3 binary buffer.
 * CRX v3 format:
 *   0-3:   magic "Cr24" (0x43723234)
 *   4-7:   version (3)
 *   8-11:  header length (little-endian)
 *   12..:  protobuf header
 *   after:  zip archive
 */
function buildCRXv3(zipContent = new Uint8Array([1, 2, 3, 4])) {
  // "Cr24" in big-endian bytes (ASCII string)
  const magic = new Uint8Array([0x43, 0x72, 0x32, 0x34]);
  const version = new Uint8Array([0x03, 0x00, 0x00, 0x00]); // v3, LE

  // Minimal valid protobuf header that Chrome accepts (empty message)
  const protoHeader = new Uint8Array([0x00]); // just a 1-byte empty protobuf
  // CRX v3 uses little-endian for header length
  const headerLen = new Uint8Array([
    protoHeader.length,
    protoHeader.length >> 8,
    0,
    0,
  ]);

  const totalLength = magic.length + version.length + headerLen.length + protoHeader.length + zipContent.length;
  const buffer = new Uint8Array(totalLength);
  buffer.set(magic, 0);
  buffer.set(version, 4);
  buffer.set(headerLen, 8);
  buffer.set(protoHeader, 12);
  buffer.set(zipContent, 12 + protoHeader.length);

  return buffer.buffer;
}

/**
 * Build a minimal valid CRX v2 binary buffer.
 * CRX v2 format:
 *   0-3:   magic "Cr24"
 *   4-7:   version (2)
 *   8-11:  public key length (le)
 *   12-15: signature length (le)
 *   16..:  public key + signature + zip
 */
function buildCRXv2(
  zipContent = new Uint8Array([1, 2, 3, 4]),
  publicKey = new Uint8Array([9, 9, 9, 9]),
  signature = new Uint8Array([8, 8, 8, 8]),
) {
  const magic = new Uint8Array([0x43, 0x72, 0x32, 0x34]);
  const version = new Uint8Array([0x02, 0x00, 0x00, 0x00]); // v2, LE

  // CRX v2 uses little-endian for lengths
  const pkLen = new Uint8Array([publicKey.length, 0, 0, 0]);
  const sigLen = new Uint8Array([signature.length, 0, 0, 0]);

  const header = 16;
  const total = header + publicKey.length + signature.length + zipContent.length;
  const buffer = new Uint8Array(total);
  buffer.set(magic, 0);
  buffer.set(version, 4);
  buffer.set(pkLen, 8);
  buffer.set(sigLen, 12);
  buffer.set(publicKey, header);
  buffer.set(signature, header + publicKey.length);
  buffer.set(zipContent, header + publicKey.length + signature.length);

  return buffer.buffer;
}

describe('CRXFileParser', () => {
  describe('CRX v3', () => {
    it('should extract zipArchiveBuffer from a valid v3 file', () => {
      const zipContent = new Uint8Array([0x50, 0x4b, 0x03, 0x04]); // PK zip magic
      const buffer = buildCRXv3(zipContent);
      const view = new DataView(buffer);
      const parser = new CRXFileParser(null); // no file needed for parse()

      const result = parser.parse(view, buffer);
      expect(result).toBeDefined();
      if (result) {
        const [zipBuf] = result;
        const arr = new Uint8Array(zipBuf);
        expect(arr[0]).toBe(0x50); // 'P'
        expect(arr[1]).toBe(0x4b); // 'K'
        expect(arr.length).toBe(4);
      }
    });

    it('should return undefined for invalid magic number', () => {
      const badData = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]);
      const view = new DataView(badData.buffer);
      const parser = new CRXFileParser(null);

      const result = parser.parse(view, badData.buffer);
      expect(result).toBeUndefined();
    });
  });

  describe('CRX v2', () => {
    it('should extract zipArchiveBuffer from a valid v2 file', () => {
      const zipContent = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);
      const buffer = buildCRXv2(zipContent);
      const view = new DataView(buffer);
      const parser = new CRXFileParser(null);

      const result = parser.parse(view, buffer);
      expect(result).toBeDefined();
      if (result) {
        const [zipBuf] = result;
        const arr = new Uint8Array(zipBuf);
        expect(arr[0]).toBe(0x50);
        expect(arr[1]).toBe(0x4b);
        expect(arr.length).toBe(4);
      }
    });

    it('should extract public key and signature from v2 file', () => {
      const pk = new Uint8Array([0x41, 0x42, 0x43]);
      const sig = new Uint8Array([0x51, 0x52]);
      const zipContent = new Uint8Array([0x01]);
      const buffer = buildCRXv2(zipContent, pk, sig);
      const view = new DataView(buffer);
      const parser = new CRXFileParser(null);

      const result = parser.parse(view, buffer);
      expect(result).toBeDefined();
      if (result) {
        const [, pkBuf, sigBuf] = result;
        expect(pkBuf).toBeDefined();
        expect(sigBuf).toBeDefined();
        if (pkBuf) {
          expect(pkBuf.byteLength).toBe(3);
        }
        if (sigBuf) {
          expect(sigBuf.byteLength).toBe(2);
        }
      }
    });
  });

  describe('Edge cases', () => {
    it('should handle empty zip content in v3', () => {
      const buffer = buildCRXv3(new Uint8Array(0));
      const view = new DataView(buffer);
      const parser = new CRXFileParser(null);

      const result = parser.parse(view, buffer);
      expect(result).toBeDefined();
      if (result) {
        const [zipBuf] = result;
        expect(zipBuf.byteLength).toBe(0);
      }
    });

    it('should handle empty zip content in v2', () => {
      const buffer = buildCRXv2(new Uint8Array(0));
      const view = new DataView(buffer);
      const parser = new CRXFileParser(null);

      const result = parser.parse(view, buffer);
      expect(result).toBeDefined();
      if (result) {
        const [zipBuf] = result;
        expect(zipBuf.byteLength).toBe(0);
      }
    });

    it('should return undefined for too-short buffer', () => {
      const tiny = new Uint8Array([0x34, 0x32]);
      const view = new DataView(tiny.buffer);
      const parser = new CRXFileParser(null);

      // Parser now returns early with undefined for buffers < 12 bytes
      const result = parser.parse(view, tiny.buffer);
      expect(result).toBeUndefined();
    });
  });
});
