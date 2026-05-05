import { defineConfig } from 'vite';

/**
 * Vite plugin: strip crossorigin from module <script> tags.
 * Firefox CSP script-src 'self' rejects crossorigin (anonymous) requests,
 * so we remove the attribute that Vite adds by default.
 */
function stripCrossorigin() {
  return {
    name: 'strip-crossorigin',
    transformIndexHtml(html) {
      return html.replace(
        /(<script[^>]*type="module"[^>]*)\scrossorigin(?=\s|>)/g,
        '$1'
      );
    },
  };
}

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
    // Disable Vite's module preload polyfill injection.
    // With inlineDynamicImports the bundle has zero chunks — preloading is pointless,
    // and the polyfill's fetch()/link-rel-modulepreload fails under CSP in Firefox.
    modulePreload: false,
  },
  plugins: [stripCrossorigin()],
  server: {
    port: 3000,
    open: true,
  },
});
