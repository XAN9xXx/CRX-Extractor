import { describe, it, expect } from 'vitest';
import { CRXReviewer } from '../src/crx-reviewer.js';
import JSZip from 'jszip';

async function buildExtensionZip(manifest, jsFiles) {
  if (jsFiles === void 0) { jsFiles = []; }
  const zip = new JSZip();
  zip.file('manifest.json', JSON.stringify(manifest, null, 2));
  for (const f of jsFiles) {
    zip.file(f.name, f.code);
  }
  return zip.generateAsync({ type: 'arraybuffer' });
}

describe('CRXReviewer — extra coverage', function () {
  describe('CSP analysis', function () {
    it('should detect unsafe-eval in CSP', async function () {
      const manifest = {
        manifest_version: 2,
        name: 'Unsafe Eval',
        version: '1.0',
        content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'",
      };
      const buffer = await buildExtensionZip(manifest);
      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      const cspIssue = result.issues.find(function (i) {
        return i.category === 'csp' && i.detail.indexOf('eval()') !== -1;
      });
      expect(cspIssue).toBeDefined();
      expect(cspIssue.severity).toBe('high');
    });

    it('should detect wildcard in CSP', async function () {
      const manifest = {
        manifest_version: 2,
        name: 'Wildcard CSP',
        version: '1.0',
        content_security_policy: "script-src *; object-src 'self'",
      };
      const buffer = await buildExtensionZip(manifest);
      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      const cspIssue = result.issues.find(function (i) {
        return i.category === 'csp' && i.detail.indexOf('wildcard') !== -1;
      });
      expect(cspIssue).toBeDefined();
    });

    it('should flag missing CSP in MV2', async function () {
      const manifest = {
        manifest_version: 2,
        name: 'No CSP',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest);
      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      const cspIssue = result.issues.find(function (i) {
        return i.category === 'csp' && i.detail.indexOf('No Content Security Policy') !== -1;
      });
      expect(cspIssue).toBeDefined();
      expect(cspIssue.severity).toBe('medium');
    });

    it('should NOT flag missing CSP for MV3', async function () {
      const manifest = {
        manifest_version: 3,
        name: 'MV3 No CSP',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest);
      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      const cspIssue = result.issues.find(function (i) {
        return i.category === 'csp' && i.detail.indexOf('No Content Security Policy') !== -1;
      });
      expect(cspIssue).toBeUndefined();
    });
  });

  describe('Content scripts analysis', function () {
    it('should detect broad content script match', async function () {
      const manifest = {
        manifest_version: 3,
        name: 'Broad CS',
        version: '1.0',
        content_scripts: [{ matches: ['<all_urls>'], js: ['inject.js'] }],
      };
      const buffer = await buildExtensionZip(manifest);
      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      const csIssue = result.issues.find(function (i) {
        return i.category === 'content_scripts';
      });
      expect(csIssue).toBeDefined();
      expect(csIssue.detail.indexOf('<all_urls>')).not.toBe(-1);
    });
  });

  describe('Review timeout', function () {
    it('reviewWithTimeout fallback on very short timeout', async function () {
      const manifest = {
        manifest_version: 3,
        name: 'Fast',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest);
      const reviewer = new CRXReviewer();
      const result = await reviewer.reviewWithTimeout(buffer, 1);
      expect(result._error || result.riskLevel).toBeDefined();
    });

    it('reviewWithTimeout completes with sufficient time', async function () {
      const manifest = {
        manifest_version: 3,
        name: 'Normal',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest);
      const reviewer = new CRXReviewer();
      const result = await reviewer.reviewWithTimeout(buffer, 5000);
      expect(result._error).toBeUndefined();
      expect(result.riskLevel).toBeDefined();
      expect(result.score).toBeGreaterThanOrEqual(80);
    });
  });

  describe('Remote script comment filtering', function () {
    it('should NOT flag URL in comments', async function () {
      const manifest = {
        manifest_version: 3,
        name: 'Commented',
        version: '1.0',
      };
      var end = '*' + '/';
      var block = '/' + '* "https://evil.com/payload.js" ' + end;
      var codeStr = '// "https://evil.com/payload.js"\n' + block + '\nconsole.log(1);';
      const buffer = await buildExtensionZip(manifest, [
        { name: 'lib.js', code: codeStr },
      ]);
      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      const remoteIssue = result.issues.find(function (i) {
        return i.category === 'remote_resources';
      });
      expect(remoteIssue).toBeUndefined();
    });
  });
});
