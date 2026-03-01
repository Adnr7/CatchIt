/**
 * CatchIt — Popup Script
 * Fetches analysis results from background worker and renders the UI.
 */

document.addEventListener('DOMContentLoaded', () => {

    const DOM = {
        loadingState: document.getElementById('loadingState'),
        resultsSection: document.getElementById('resultsSection'),
        errorState: document.getElementById('errorState'),
        headerStatus: document.getElementById('headerStatus'),
        statusDot: document.getElementById('statusDot'),
        statusText: document.getElementById('statusText'),
        scoreRingFill: document.getElementById('scoreRingFill'),
        scoreValue: document.getElementById('scoreValue'),
        riskBadge: document.getElementById('riskBadge'),
        riskBadgeDot: document.getElementById('riskBadgeDot'),
        riskBadgeText: document.getElementById('riskBadgeText'),
        siteDomain: document.getElementById('siteDomain'),
        sslIcon: document.getElementById('sslIcon'),
        sslStatus: document.getElementById('sslStatus'),
        scanTime: document.getElementById('scanTime'),
        signalsSection: document.getElementById('signalsSection'),
        signalsList: document.getElementById('signalsList'),
        fieldsSection: document.getElementById('fieldsSection'),
        fieldsList: document.getElementById('fieldsList'),
        recommendationCard: document.getElementById('recommendationCard'),
        recommendationIcon: document.getElementById('recommendationIcon'),
        recommendationText: document.getElementById('recommendationText'),
        actionsSection: document.getElementById('actionsSection'),
        btnGoBack: document.getElementById('btnGoBack')
    };

    const CIRCUMFERENCE = 2 * Math.PI * 52; // r=52

    /**
     * Request results from background with timeout fallback
     */
    function fetchResults() {
        // Guard: if chrome.runtime is unavailable (e.g. opened as a file)
        if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
            showError();
            return;
        }

        let responded = false;

        // Timeout — if background doesn't respond in 3 seconds, try fallback
        const timeout = setTimeout(() => {
            if (!responded) {
                responded = true;
                tryFallbackAnalysis();
            }
        }, 3000);

        try {
            chrome.runtime.sendMessage({ type: 'GET_RESULTS' }, (results) => {
                if (responded) return; // Already timed out
                responded = true;
                clearTimeout(timeout);

                if (chrome.runtime.lastError) {
                    tryFallbackAnalysis();
                    return;
                }

                if (!results || results.error) {
                    tryFallbackAnalysis();
                    return;
                }

                renderResults(results);
            });
        } catch (e) {
            if (!responded) {
                responded = true;
                clearTimeout(timeout);
                tryFallbackAnalysis();
            }
        }
    }

    /**
     * Fallback: query the active tab and do a basic URL-only analysis
     */
    function tryFallbackAnalysis() {
        try {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (chrome.runtime.lastError || !tabs || !tabs[0] || !tabs[0].url) {
                    showError();
                    return;
                }

                const tab = tabs[0];
                const url = tab.url;

                // Skip internal pages
                if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
                    url.startsWith('about:') || url.startsWith('edge://')) {
                    showError();
                    return;
                }

                // Basic URL-only analysis in the popup itself
                const domain = (() => { try { return new URL(url).hostname; } catch (e) { return url; } })();
                const isHTTPS = url.startsWith('https://');

                // Simple heuristic score
                let score = 0;
                const signals = [];

                if (!isHTTPS) { score += 15; signals.push('Site does not use HTTPS encryption'); }
                if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) { score += 30; signals.push('URL uses IP address instead of domain name'); }

                const suspiciousTLDs = ['.xyz', '.top', '.club', '.buzz', '.gq', '.ml', '.cf', '.ga', '.tk', '.icu', '.zip', '.mov'];
                const tld = '.' + domain.split('.').pop();
                if (suspiciousTLDs.includes(tld)) { score += 15; signals.push('Suspicious top-level domain: ' + tld); }

                if (domain.split('.').length > 4) { score += 15; signals.push('Excessive subdomains in URL'); }
                if (url.length > 200) { score += 8; signals.push('Unusually long URL'); }

                score = Math.min(score, 100);
                let level, label, color;
                if (score <= 30) { level = 'safe'; label = 'Safe'; color = '#00e676'; }
                else if (score <= 65) { level = 'suspicious'; label = 'Suspicious'; color = '#ffd600'; }
                else { level = 'dangerous'; label = 'Dangerous'; color = '#ff1744'; }

                let recommendation = 'This website appears safe. Browse normally.';
                if (level === 'suspicious') recommendation = 'This site shows some suspicious indicators. Proceed with caution.';
                if (level === 'dangerous') recommendation = 'This website is likely dangerous. Leave immediately.';

                if (signals.length === 0) signals.push('Basic URL analysis only — full scan requires page reload');

                renderResults({
                    url,
                    domain,
                    isHTTPS,
                    riskScore: score,
                    classification: { level, label, color },
                    signals,
                    sensitiveFields: [],
                    recommendation,
                    analyzedAt: new Date().toISOString()
                });
            });
        } catch (e) {
            showError();
        }
    }

    /**
     * Show error state
     */
    function showError() {
        DOM.loadingState.style.display = 'none';
        DOM.resultsSection.style.display = 'none';
        DOM.errorState.style.display = 'flex';
        DOM.statusDot.className = 'status-dot';
        DOM.statusText.textContent = 'Unavailable';
    }

    /**
     * Render analysis results
     */
    function renderResults(data) {
        DOM.loadingState.style.display = 'none';
        DOM.errorState.style.display = 'none';
        DOM.resultsSection.style.display = 'block';

        const level = data.classification?.level || 'safe';
        const score = data.riskScore || 0;

        // ─── Header Status ───
        DOM.statusDot.className = `status-dot ${level}`;
        DOM.statusDot.style.animation = 'none';
        DOM.statusText.textContent = capitalize(level);

        // ─── Score Ring ───
        const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
        const ringColor = data.classification?.color || '#22c55e';

        // Delay for animation effect
        requestAnimationFrame(() => {
            DOM.scoreRingFill.style.stroke = ringColor;
            DOM.scoreRingFill.style.strokeDashoffset = offset;
        });

        // Animate score counter
        animateCounter(DOM.scoreValue, 0, score, 800);

        // ─── Risk Badge ───
        DOM.riskBadge.className = `risk-badge ${level}`;
        DOM.riskBadgeText.textContent = data.classification?.label || 'Unknown';

        // ─── Site Info ───
        DOM.siteDomain.textContent = data.domain || '—';
        DOM.siteDomain.title = data.url || '';

        if (data.isHTTPS) {
            DOM.sslIcon.textContent = '🔒';
            DOM.sslStatus.textContent = 'Secure (HTTPS)';
            DOM.sslStatus.style.color = '#00e676';
        } else {
            DOM.sslIcon.textContent = '🔓';
            DOM.sslStatus.textContent = 'Not Secure (HTTP)';
            DOM.sslStatus.style.color = '#ff1744';
        }

        // Scan time
        if (data.analyzedAt) {
            const date = new Date(data.analyzedAt);
            DOM.scanTime.textContent = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }

        // ─── Signals ───
        if (data.signals && data.signals.length > 0) {
            DOM.signalsSection.style.display = 'block';
            DOM.signalsList.innerHTML = '';

            data.signals.forEach(signal => {
                const li = document.createElement('li');
                const bulletClass = level === 'dangerous' ? 'danger' : 'warning';
                li.innerHTML = `
          <span class="signal-bullet ${bulletClass}">
            ${level === 'dangerous' ? '🔴' : '🟡'}
          </span>
          <span>${escapeHTML(signal)}</span>
        `;
                DOM.signalsList.appendChild(li);
            });
        } else {
            DOM.signalsSection.style.display = 'none';
        }

        // ─── Sensitive Fields ───
        if (data.sensitiveFields && data.sensitiveFields.length > 0) {
            DOM.fieldsSection.style.display = 'block';
            DOM.fieldsList.innerHTML = '';

            data.sensitiveFields.forEach(field => {
                const li = document.createElement('li');
                li.innerHTML = `🔑 <span>${escapeHTML(field.label)}</span>`;
                DOM.fieldsList.appendChild(li);
            });
        } else {
            DOM.fieldsSection.style.display = 'none';
        }

        // ─── Recommendation ───
        DOM.recommendationCard.className = `recommendation-card ${level}`;
        DOM.recommendationText.textContent = data.recommendation || 'No recommendation available.';

        const icons = { safe: '✅', suspicious: '⚠️', dangerous: '🛑' };
        DOM.recommendationIcon.textContent = icons[level] || '💡';

        // ─── Actions ───
        if (level === 'suspicious' || level === 'dangerous') {
            DOM.actionsSection.style.display = 'block';
        } else {
            DOM.actionsSection.style.display = 'none';
        }
    }

    /**
     * Animate a counter from start to end
     */
    function animateCounter(element, start, end, duration) {
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
            const current = Math.round(start + (end - start) * eased);
            element.textContent = current;

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    }

    /**
     * Capitalize first letter
     */
    function capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    /**
     * Escape HTML entities
     */
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ─── Go Back Button ───
    DOM.btnGoBack.addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.goBack(tabs[0].id);
                window.close();
            }
        });
    });

    // ─── Init ───
    fetchResults();

});
