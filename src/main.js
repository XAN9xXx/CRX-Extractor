/**
 * CRX Extractor — Main UI logic (ES6+, no jQuery)
 */
import { CRXFileParser } from './crx-parser.js';
import { CRXReviewer } from './crx-reviewer.js';

// ── Animation helpers ───────────────────────────────────────────────────────
const TRANSITION_DURATION = 200; // ms ("fast")

/**
 * Fade in an element. Automatically sets display:'' and transitions opacity 0→1.
 * @param {HTMLElement} el
 * @param {number} [duration=200]
 * @returns {Promise<void>}
 */
function fadeIn(el, duration = TRANSITION_DURATION) {
  return new Promise((resolve) => {
    const display = el.dataset.fadeDisplay || '';
    el.style.display = display;
    el.style.opacity = '0';
    el.style.transition = `opacity ${duration}ms ease`;

    let settled = false;
    let fallback; // declared in outer scope so done() can access it
    const done = () => {
      if (settled) return;
      settled = true;
      el.removeEventListener('transitionend', onEnd);
      clearTimeout(fallback);
      el.style.transition = '';
      resolve();
    };
    const onEnd = () => done();

    requestAnimationFrame(() => {
      el.style.opacity = '1';
      el.addEventListener('transitionend', onEnd, { once: true });
      // Safety fallback: if transitionend doesn't fire, resolve anyway
      fallback = setTimeout(done, duration + 80);
    });
  });
}

/**
 * Fade out an element. Sets display:none after transition.
 * @param {HTMLElement} el
 * @param {number} [duration=200]
 * @returns {Promise<void>}
 */
function fadeOut(el, duration = TRANSITION_DURATION) {
  return new Promise((resolve) => {
    el.style.transition = `opacity ${duration}ms ease`;
    el.style.opacity = '0';

    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      el.removeEventListener('transitionend', onEnd);
      clearTimeout(fallback);
      el.style.display = 'none';
      el.style.transition = '';
      resolve();
    };
    const onEnd = () => done();

    el.addEventListener('transitionend', onEnd, { once: true });
    const fallback = setTimeout(done, duration + 80);
  });
}

/** Show immediately (no animation, clear inline display/opacity overrides) */
function showEl(el) {
  el.style.transition = '';
  el.style.display = el.dataset.fadeDisplay || '';
  el.style.opacity = '1';
}

/** Hide immediately (no animation) */
function hideEl(el) {
  el.style.transition = '';
  el.style.display = 'none';
  el.style.opacity = '';
}

/**
 * Tag elements with their natural display value so fadeIn/showEl can restore it.
 * Elements that start with display:none in CSS will be tagged with their
 * expected display when first shown.
 */
function tagDisplay(el, display) {
  if (!el.dataset.fadeDisplay) {
    el.dataset.fadeDisplay = display;
  }
}

// ── DOM references ──────────────────────────────────────────────────────────
const $ = (sel, ctx = document) => ctx.querySelector(sel);

// Download .CRX section
const downloadCrxButton = $('.download-crx');
const downloadCrxOkButton = $('.download-crx-ok');
const downloadCrxInput = $('#crx-download-input');
const downloadCrxError = $('.download-crx-err');

// Review panel section
const reviewPanel = $('.review-panel');
const reviewCloseBtn = $('.review-close', reviewPanel);
const reviewTitle = $('.review-title', reviewPanel);
const reviewScoreIcon = $('.review-score-icon', reviewPanel);
const reviewScore = $('.review-score', reviewPanel);
const reviewLevel = $('.review-level', reviewPanel);
const reviewStats = $('.review-stats', reviewPanel);
const reviewIssues = $('.review-issues', reviewPanel);

// Drop zone section
const dropZone = $('#drop-zone');
const inputFile = $('input[type="file"]', dropZone);
const downloadSourceBtn = $('.download', dropZone);
const downloadResetBtn = $('.download-reset', dropZone);
const thanks = $('.thanks', dropZone);
const dropZoneUiWrapper = $('.ui-wrapper', dropZone);
const dropZoneLoading = $('.loading-wrapper', dropZone);
const downloadSourceError = $('.download-source-err');

const MOUSE_OVER_CLASS = 'mouse-over';
const UPLOAD_DISABLED_CLASS = 'upload-disabled';
let lastObjectUrl = null;

// Tag display values for elements that animate
tagDisplay(thanks, 'block');
tagDisplay(dropZoneUiWrapper, 'block');
tagDisplay(dropZoneLoading, 'flex');
tagDisplay(downloadSourceBtn, 'inline-block');
tagDisplay(downloadResetBtn, 'flex');
tagDisplay(downloadCrxButton, 'inline-block');
tagDisplay(downloadCrxOkButton, 'inline-block');
tagDisplay(downloadCrxError, 'block');
tagDisplay(downloadSourceError, 'block');
tagDisplay(reviewPanel, 'flex');

// ── Download .CRX from Chrome WebStore ──────────────────────────────────────

function showCrxDownloadError(msg) {
  console.warn(msg);
  $('p', downloadCrxError).textContent = msg;
  fadeIn(downloadCrxError);
}

function hideCrxDownloadError() {
  fadeOut(downloadCrxError);
}

function getExtensionIdFromLink(link) {
  let url;
  try {
    url = new URL(link);
  } catch {
    return;
  }
  if (url.host !== 'chrome.google.com' && url.host !== 'chromewebstore.google.com') {
    return;
  }
  const segments = url.pathname.replace(/\/$/, '').split('/');
  return segments.pop();
}

function buildDownloadLink(extensionId) {
  const baseUrl = 'https://clients2.google.com/service/update2/crx?response=redirect&prodversion=49.0&acceptformat=crx3&x=id%3D***%26installsource%3Dondemand%26uc';
  return baseUrl.replace('***', extensionId);
}

downloadCrxOkButton.addEventListener('click', () => {
  hideCrxDownloadError();

  const rawLink = downloadCrxInput.value;
  const extensionId = getExtensionIdFromLink(rawLink);
  const downloadLink = buildDownloadLink(extensionId);

  if (!extensionId || !downloadLink) {
    showCrxDownloadError('The provided link is not a Chrome Extension link from Chrome WebStore.');
    return;
  }

  downloadCrxButton.href = downloadLink;
  downloadCrxButton.download = 'extension.crx';
  fadeOut(downloadCrxOkButton).then(() => fadeIn(downloadCrxButton));
});

downloadCrxButton.addEventListener('click', () => {
  fadeOut(downloadCrxButton).then(() => {
    downloadCrxInput.value = '';
    fadeIn(downloadCrxOkButton);
  });
});

// ── Drop zone & .CRX file parsing ───────────────────────────────────────────

function getFilename(file) {
  const lastDot = file.name.lastIndexOf('.');
  return lastDot > 0 ? file.name.substring(0, lastDot) : file.name;
}

function showErrorMessage(msg) {
  console.warn('User error message: ' + msg);
  $('p', downloadSourceError).textContent = msg;
  fadeIn(downloadSourceError);
}

function showLoadingState() {
  hideEl(downloadSourceError);
  hideEl(downloadSourceBtn);
  hideEl(downloadResetBtn);
  hideEl(dropZoneUiWrapper);
  // Hide review overlay if it was open from a previous file
  hideReviewOverlay();
  // Re-enable upload during loading for next file
  dropZone.classList.remove(UPLOAD_DISABLED_CLASS);
  $('p', dropZoneLoading).textContent = 'Processing file...';
  showEl(dropZoneLoading);
}

function hideLoadingState(restoreUi) {
  hideEl(dropZoneLoading);
  if (restoreUi) {
    showEl(dropZoneUiWrapper);
  }
}

function showDownloadButton() {
  dropZone.classList.add(UPLOAD_DISABLED_CLASS);
  fadeIn(downloadSourceBtn);
  fadeIn(downloadResetBtn);
}

async function showSourceDownloadDropzone() {
  await Promise.all([
    fadeOut(downloadSourceBtn, 200),
    fadeOut(downloadResetBtn, 200),
  ]);

  // Restore ability to upload a new file
  dropZone.classList.remove(UPLOAD_DISABLED_CLASS);

  // Revoke blob URL after generous delay for browser to initiate download
  const urlToRevoke = lastObjectUrl;
  if (urlToRevoke) {
    setTimeout(() => URL.revokeObjectURL(urlToRevoke), 60000);
    lastObjectUrl = null;
  }

  await fadeIn(thanks, 600);
  await fadeOut(thanks, 600);
  await fadeIn(dropZoneUiWrapper, 600);
}

function renderReview(report) {
  // Handle error-only reports
  if (report && (report._error || report.error)) {
    reviewTitle.textContent = 'Review Unavailable';
    reviewScoreIcon.textContent = '⚠️';
    reviewScore.textContent = '—';
    reviewScore.className = 'review-score';
    reviewLevel.textContent = 'ERROR';
    reviewLevel.className = 'review-level risk-critical';
    reviewStats.innerHTML = '';
    reviewIssues.innerHTML = `<div class="review-empty">${report._error || report.error}</div>`;
    return;
  }

  if (!report || !report.riskLevel) {
    reviewTitle.textContent = 'Review Unavailable';
    reviewScoreIcon.textContent = '⚠️';
    reviewScore.textContent = '—';
    reviewScore.className = 'review-score';
    reviewLevel.textContent = 'ERROR';
    reviewLevel.className = 'review-level risk-critical';
    reviewStats.innerHTML = '';
    reviewIssues.innerHTML = '<div class="review-empty">Incomplete review data received.</div>';
    return;
  }

  const { extName, extVersion, manifestVersion, score, riskLevel, stats, issues } = report;

  // Header
  reviewTitle.textContent = `${extName}  ·  v${extVersion}  ·  MV${manifestVersion}`;
  reviewScoreIcon.textContent = riskLevel.icon;
  reviewScore.textContent = String(score);
  reviewScore.className = `review-score ${riskLevel.class}`;
  reviewLevel.textContent = riskLevel.label;
  reviewLevel.className = `review-level ${riskLevel.class}`;

  // Stats grid
  reviewStats.innerHTML = [
    `<div class="review-stat">Permissions: <span>${stats.totalPermissions}</span></div>`,
    `<div class="review-stat">Critical perms: <span>${stats.criticalPermissions}</span></div>`,
    `<div class="review-stat">Broad hosts: <span>${stats.broadHostPermissions}</span></div>`,
    `<div class="review-stat">JS files analyzed: <span>${stats.jsFilesAnalyzed}</span></div>`,
    `<div class="review-stat">Trackers found: <span>${stats.trackingDomainsFound}</span></div>`,
    `<div class="review-stat">Suspicious patterns: <span>${stats.suspiciousPatternsFound}</span></div>`,
    `<div class="review-stat">Remote scripts: <span>${stats.remoteScriptsFound}</span></div>`,
    `<div class="review-stat">Issues: <span>${stats.totalIssues}</span></div>`,
  ].join('');

  // Issues list
  if (issues.length === 0) {
    reviewIssues.innerHTML = '<div class="review-empty">✅ No issues detected. This extension appears clean.</div>';
  } else {
    reviewIssues.innerHTML = issues
      .map(
        (issue) =>
          `<div class="review-issue">
            <span class="review-issue-sev ${issue.severity}"></span>
            <span class="review-issue-detail">
              <span class="review-issue-cat">[${issue.category}]</span>${issue.detail}
            </span>
          </div>`,
      )
      .join('');
  }

}

// ── Review overlay open / close / drag ───────────────────────────────────────

/** Clamp a value between min and max. */
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

/** Compute the default position for the review panel (left 1rem, vertically centered via CSS). */
function computeReviewPosition() {
  const left = 16; // ~1rem
  return { left };
}

function showReviewOverlay() {
  // Clear any inline display/opacity/top/transform from hideEl or previous drag
  reviewPanel.style.display = '';
  reviewPanel.style.opacity = '';
  reviewPanel.style.top = '';
  reviewPanel.style.transform = '';

  reviewPanel.style.left = computeReviewPosition().left + 'px';

  reviewPanel.classList.add('review-visible');
}

function hideReviewOverlay() {
  reviewPanel.classList.remove('review-visible');
}

// ── Drag support ─────────────────────────────────────────────────────────────

let dragState = null;

reviewPanel.addEventListener('mousedown', (e) => {
  // Only drag from header area (not the close button, nor inner content)
  if (!e.target.closest('.review-header') || e.target.closest('.review-close')) return;

  // Convert CSS top:50% to pixel value for clean dragging
  const styleTop = reviewPanel.style.top;
  if (!styleTop || styleTop === '50%' || styleTop.endsWith('%')) {
    const rect = reviewPanel.getBoundingClientRect();
    reviewPanel.style.top = rect.top + 'px';
    reviewPanel.style.transform = ''; // clear translateY(-50%)
  }

  const rect = reviewPanel.getBoundingClientRect();
  dragState = {
    offsetX: e.clientX - rect.left,
    offsetY: e.clientY - rect.top,
  };

  reviewPanel.classList.add('dragging');
  e.preventDefault();
});

document.addEventListener('mousemove', (e) => {
  if (!dragState) return;

  const newLeft = clamp(
    e.clientX - dragState.offsetX,
    0,
    window.innerWidth - reviewPanel.offsetWidth
  );
  const newTop = clamp(
    e.clientY - dragState.offsetY,
    0,
    window.innerHeight - 48 // keep at least part of header visible
  );

  reviewPanel.style.left = newLeft + 'px';
  reviewPanel.style.top = newTop + 'px';
});

document.addEventListener('mouseup', () => {
  if (!dragState) return;
  dragState = null;
  reviewPanel.classList.remove('dragging');
});

// Close button
reviewCloseBtn.addEventListener('click', (e) => {
  e.stopPropagation(); // don't trigger drag
  hideReviewOverlay();
});

// ESC key to dismiss
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && reviewPanel.classList.contains('review-visible')) {
    hideReviewOverlay();
  }
});

downloadSourceBtn.addEventListener('click', showSourceDownloadDropzone);

// Reset button — go back to upload state without downloading
downloadResetBtn.addEventListener('click', (e) => {
  e.preventDefault();
  e.stopPropagation();
  hideReviewOverlay();
  showSourceDownloadDropzone();
});

function checkFileAndParse(file) {
  // Reset input value so the same file can be selected again
  // (otherwise the change event won't fire for the same file)
  inputFile.value = '';

  if (!file.name.toLowerCase().endsWith('.crx')) {
    showErrorMessage('This file seems to be of different file format. Please provide valid .CRX file.');
    return;
  }

  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
  if (file.size > MAX_FILE_SIZE) {
    showErrorMessage('File is too large. Maximum allowed size is 100 MB.');
    return;
  }

  // Revoke previous object URL
  if (lastObjectUrl) {
    URL.revokeObjectURL(lastObjectUrl);
    lastObjectUrl = null;
  }

  showLoadingState();

  // Use Web Worker if available; fall back to main-thread parser
  if (typeof Worker !== 'undefined') {
    parseWithWorker(file);
  } else {
    parseOnMainThread(file);
  }
}

function parseWithWorker(file) {
  const reader = new FileReader();
  reader.onload = (event) => {
    const buffer = event.target.result;

    // Try Worker first; fall back to main thread on any failure
    try {
      const worker = new Worker(
        new URL('./crx-parser.worker.js', import.meta.url),
        { type: 'module' }
      );

      worker.onmessage = (msg) => {
        worker.terminate();
        if (msg.data.error) {
          hideLoadingState(true);
          showErrorMessage(msg.data.error);
          return;
        }
        handleParsedZip(msg.data.zipArchiveBuffer, file).catch((err) => {
          console.warn('handleParsedZip failed:', err);
        });
      };

      worker.onerror = () => {
        worker.terminate();
        // Worker failed — silently fall through to main thread
        parseOnMainThreadWithBuffer(buffer, file);
      };

      worker.postMessage(buffer);
    } catch {
      // new Worker threw — use the buffer we already have
      parseOnMainThreadWithBuffer(buffer, file);
    }
  };

  reader.onerror = () => {
    hideLoadingState(true);
    showErrorMessage('Failed to read file.');
  };

  reader.readAsArrayBuffer(file);
}

function parseOnMainThreadWithBuffer(buffer, file) {
  const view = new DataView(buffer);
  const parser = new CRXFileParser(file);
  const result = parser.parse(view, buffer);
  if (!result) {
    hideLoadingState(true);
    showErrorMessage('Unable to parse this file. The file may be broken or an unknown error has occurred.');
    return;
  }
  handleParsedZip(result[0], file).catch((err) => {
    console.warn('handleParsedZip (main) failed:', err);
  });
}

function parseOnMainThread(file) {
  const parser = new CRXFileParser(file);
  parser.load().then((parsingResult) => {
    if (!parsingResult) {
      hideLoadingState(true);
      showErrorMessage('Unable to parse this file. The file may be broken or an unknown error has occurred.');
      return;
    }
    handleParsedZip(parsingResult[0], file).catch((err) => {
      console.warn('handleParsedZip (main) failed:', err);
    });
  }).catch(() => {
    hideLoadingState(true);
    showErrorMessage('Unable to parse this file. The file may be broken or an unknown error has occurred.');
  });
}

async function handleParsedZip(zipArchiveBuffer, file) {
  try {
    // Create download URL immediately
    const outputFile = new Blob([zipArchiveBuffer], { type: 'application/zip' });
    lastObjectUrl = URL.createObjectURL(outputFile);
    downloadSourceBtn.href = lastObjectUrl;
    downloadSourceBtn.download = getFilename(file) + '.zip';

    // Run privacy/security review (15s timeout)
    $('p', dropZoneLoading).textContent = 'Analyzing extension...';

    const reviewer = new CRXReviewer();
    const reviewResult = await reviewer.reviewWithTimeout(zipArchiveBuffer, 15000);

    // Always show the review overlay
    renderReview(reviewResult || { _error: 'No review data returned.' });
    showReviewOverlay();
  } catch (err) {
    console.warn('Review pipeline error:', err);
    renderReview({ _error: 'An unexpected error occurred during review. The source code is still downloadable below.' });
    showReviewOverlay();
  } finally {
    // Don't restore drop zone UI — keep it clean, only show download button
    hideLoadingState(false);
    showDownloadButton();
  }
}

// ── Drag & drop events ──────────────────────────────────────────────────────

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  e.stopPropagation();
  dropZone.classList.add(MOUSE_OVER_CLASS);
});

dropZone.addEventListener('dragleave', (e) => {
  e.preventDefault();
  e.stopPropagation();
  dropZone.classList.remove(MOUSE_OVER_CLASS);
});

// Open file dialog when user clicks anywhere on the drop zone
// (not just on the small file input button at the bottom)
dropZone.addEventListener('click', (e) => {
  // Skip if upload is disabled (e.g. download button is showing)
  if (dropZone.classList.contains(UPLOAD_DISABLED_CLASS)) return;
  // Don't open file dialog if user clicks download button, its wrapper,
  // or the file input itself (which already opens the native dialog)
  if (!e.target.closest('.download, .download-btn-wrapper, input[type="file"]')) {
    inputFile.click();
  }
});

inputFile.addEventListener('change', () => {
  const { files } = inputFile;
  if (files.length !== 1) {
    showErrorMessage('You should put only one .CRX file at a time.');
    return;
  }
  checkFileAndParse(files[0]);
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  e.stopPropagation();
  dropZone.classList.remove(MOUSE_OVER_CLASS);

  if (e.dataTransfer && e.dataTransfer.files.length > 0) {
    if (e.dataTransfer.files.length === 1) {
      checkFileAndParse(e.dataTransfer.files[0]);
    } else {
      showErrorMessage('You should put only one .CRX file at a time.');
    }
  } else {
    showErrorMessage('Only .CRX files supported!');
  }
});
