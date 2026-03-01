/**
 * CatchIt — Content Script
 * Extracts page data, detects sensitive forms, monitors downloads,
 * and injects warning banners.
 */

(() => {
    // Prevent double-injection
    if (window.__catchItInjected) return;
    window.__catchItInjected = true;

    const BANNER_ID = 'catchit-warning-banner';
    const OVERLAY_ID = 'catchit-form-overlay';

    // ─── Page Data Extraction ───

    /**
     * Extract visible text from the page
     */
    function extractPageText() {
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            {
                acceptNode(node) {
                    const parent = node.parentElement;
                    if (!parent) return NodeFilter.FILTER_REJECT;
                    const tag = parent.tagName;
                    if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'SVG', 'PATH'].includes(tag)) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    const style = getComputedStyle(parent);
                    if (style.display === 'none' || style.visibility === 'hidden') {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return NodeFilter.FILTER_ACCEPT;
                }
            }
        );

        let text = '';
        let count = 0;
        const MAX_CHARS = 15000;

        while (walker.nextNode() && count < MAX_CHARS) {
            const val = walker.currentNode.textContent.trim();
            if (val.length > 1) {
                text += val + ' ';
                count += val.length;
            }
        }

        // Also include title and meta description
        const title = document.title || '';
        const metaDesc = document.querySelector('meta[name="description"]')?.content || '';

        return `${title} ${metaDesc} ${text}`.substring(0, MAX_CHARS);
    }

    /**
     * Extract form field information
     */
    function extractFormData() {
        const fields = [];
        const inputs = document.querySelectorAll('input, select, textarea');

        inputs.forEach(input => {
            fields.push({
                type: input.type || 'text',
                name: input.name || '',
                id: input.id || '',
                placeholder: input.placeholder || '',
                autocomplete: input.autocomplete || '',
                formAction: input.form?.action || ''
            });
        });

        return { fields, formCount: document.forms.length };
    }

    // ─── Warning Banner ───

    /**
     * Inject a warning banner at the top of the page
     */
    function showWarningBanner(data) {
        // Remove existing banner if any
        const existing = document.getElementById(BANNER_ID);
        if (existing) existing.remove();

        const level = data.classification.level;
        const isDANGER = level === 'dangerous';

        const banner = document.createElement('div');
        banner.id = BANNER_ID;
        banner.setAttribute('role', 'alert');
        banner.setAttribute('aria-live', 'assertive');

        // Build reason list (max 3)
        const reasons = (data.signals || []).slice(0, 3).map(r => `<li>${escapeHTML(r)}</li>`).join('');

        banner.innerHTML = `
      <div class="catchit-banner-inner ${isDANGER ? 'catchit-danger' : 'catchit-warning'}">
        <div class="catchit-banner-icon">
          ${isDANGER ? '🛑' : '⚠️'}
        </div>
        <div class="catchit-banner-content">
          <div class="catchit-banner-title">
            ${isDANGER ? 'CatchIt: Dangerous Website Detected!' : 'CatchIt: Suspicious Website Detected'}
          </div>
          <div class="catchit-banner-subtitle">
            Risk Score: <strong>${data.riskScore}/100</strong> — ${escapeHTML(data.recommendation)}
          </div>
          ${reasons ? `<ul class="catchit-banner-reasons">${reasons}</ul>` : ''}
        </div>
        <div class="catchit-banner-actions">
          <button class="catchit-btn-back" title="Go back to safety">← Go Back</button>
          <button class="catchit-btn-dismiss" title="Dismiss warning">✕</button>
        </div>
      </div>
    `;

        document.body.prepend(banner);

        // Event listeners
        banner.querySelector('.catchit-btn-dismiss')?.addEventListener('click', () => {
            banner.classList.add('catchit-banner-hide');
            setTimeout(() => banner.remove(), 300);
        });

        banner.querySelector('.catchit-btn-back')?.addEventListener('click', () => {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = 'about:blank';
            }
        });
    }

    // ─── Form Submission Guard ───

    /**
     * Show form warning overlay on high-risk sites
     */
    function guardSensitiveForms(data) {
        if (!data.sensitiveFields || data.sensitiveFields.length === 0) return;
        if (data.riskScore <= 30) return;

        // Attach to all forms on the page
        document.querySelectorAll('form').forEach(form => {
            if (form.__catchItGuarded) return;
            form.__catchItGuarded = true;

            form.addEventListener('submit', (e) => {
                // Check if any sensitive fields are filled
                const hasSensitiveData = data.sensitiveFields.some(sf => {
                    const input = form.querySelector(`[name="${sf.fieldName}"], [id="${sf.fieldName}"]`);
                    return input && input.value && input.value.length > 0;
                });

                if (hasSensitiveData) {
                    e.preventDefault();
                    e.stopPropagation();
                    showFormWarning(form, data);
                }
            });
        });
    }

    /**
     * Show form submission warning dialog
     */
    function showFormWarning(form, data) {
        const existing = document.getElementById(OVERLAY_ID);
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = OVERLAY_ID;

        const fieldList = data.sensitiveFields
            .map(f => `<li>🔑 ${escapeHTML(f.label)}</li>`)
            .join('');

        overlay.innerHTML = `
      <div class="catchit-overlay-backdrop">
        <div class="catchit-overlay-dialog">
          <div class="catchit-overlay-icon">🛡️</div>
          <h2>CatchIt — Sensitive Data Warning</h2>
          <p>You are about to submit sensitive information on a <strong style="color: ${data.classification.color}">${data.classification.label}</strong> website (Risk Score: ${data.riskScore}/100).</p>
          <ul class="catchit-overlay-fields">${fieldList}</ul>
          <p class="catchit-overlay-question">Are you sure you want to proceed?</p>
          <div class="catchit-overlay-actions">
            <button class="catchit-overlay-cancel">Cancel Submission</button>
            <button class="catchit-overlay-proceed">Proceed Anyway</button>
          </div>
        </div>
      </div>
    `;

        document.body.appendChild(overlay);

        overlay.querySelector('.catchit-overlay-cancel').addEventListener('click', () => {
            overlay.remove();
        });

        overlay.querySelector('.catchit-overlay-proceed').addEventListener('click', () => {
            overlay.remove();
            form.__catchItGuarded = false;
            form.submit();
        });
    }

    // ─── Download Protection ───

    /**
     * Monitor download links
     */
    function monitorDownloads() {
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a[href]');
            if (!link) return;

            const href = link.href || link.getAttribute('href');
            if (!href) return;

            // Check with background
            chrome.runtime.sendMessage({ type: 'CHECK_DOWNLOAD', url: href }, (result) => {
                if (chrome.runtime.lastError || !result || !result.dangerous) return;

                e.preventDefault();
                e.stopPropagation();

                const proceed = confirm(
                    `⚠️ CatchIt Download Warning\n\n` +
                    `This link points to a potentially dangerous file type:\n` +
                    `${result.extension}\n\n` +
                    `${result.reason}\n\n` +
                    `Do you want to proceed with the download?`
                );

                if (proceed) {
                    window.location.href = href;
                }
            });
        }, true);
    }

    // ─── Utility ───

    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ─── Message Handler ───

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === 'EXTRACT_PAGE_DATA') {
            const text = extractPageText();
            const formData = extractFormData();
            sendResponse({ text, formData, url: window.location.href });
            return false;
        }

        if (message.type === 'SHOW_WARNING') {
            showWarningBanner(message.data);
            guardSensitiveForms(message.data);
            return false;
        }
    });

    // ─── Initialize ───

    // Send page data to background proactively
    function init() {
        const text = extractPageText();
        const formData = extractFormData();

        chrome.runtime.sendMessage({
            type: 'PAGE_DATA',
            text,
            formData,
            url: window.location.href
        });

        // Start download monitoring
        monitorDownloads();
    }

    // Run after a small delay to let the page fully render
    if (document.readyState === 'complete') {
        setTimeout(init, 500);
    } else {
        window.addEventListener('load', () => setTimeout(init, 500));
    }

})();
