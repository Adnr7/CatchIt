/**
 * CatchIt — Background Service Worker
 * Orchestrates analysis, icon updates, and message routing.
 * Self-contained: includes the AI analyzer inline to avoid importScripts issues.
 */

// ═══════════════════════════════════════════════
// INLINE AI ANALYZER (avoids importScripts)
// ═══════════════════════════════════════════════

const CatchItAnalyzer = (() => {

    const SUSPICIOUS_TLDS = [
        '.xyz', '.top', '.club', '.work', '.buzz', '.gq', '.ml', '.cf', '.ga', '.tk',
        '.icu', '.cam', '.rest', '.surf', '.monster', '.quest', '.click', '.link',
        '.support', '.review', '.stream', '.download', '.win', '.bid', '.trade',
        '.racing', '.cricket', '.science', '.party', '.accountant', '.date', '.faith',
        '.loan', '.men', '.zip', '.mov'
    ];

    const IMPERSONATION_TARGETS = [
        'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook',
        'instagram', 'whatsapp', 'twitter', 'linkedin', 'chase', 'wellsfargo',
        'bankofamerica', 'citibank', 'usps', 'fedex', 'dhl', 'ups', 'irs',
        'hmrc', 'gov', 'dropbox', 'adobe', 'yahoo', 'outlook', 'office365',
        'icloud', 'coinbase', 'binance', 'blockchain', 'steam', 'epicgames',
        'roblox', 'telegram', 'discord', 'spotify', 'uber', 'airbnb',
        'sbi', 'hdfc', 'icici', 'paytm', 'phonepe', 'gpay'
    ];

    const SCAM_PATTERNS = [
        { pattern: /your\s+account\s+(has\s+been|is)\s+(suspended|locked|compromised|limited)/i, weight: 25, reason: 'Account suspension threat detected' },
        { pattern: /immediate\s+(action|attention)\s+required/i, weight: 20, reason: 'Urgent action pressure tactic' },
        { pattern: /verify\s+your\s+(identity|account|information)/i, weight: 18, reason: 'Identity verification request' },
        { pattern: /unauthorized\s+(access|activity|transaction)/i, weight: 20, reason: 'Unauthorized activity scare tactic' },
        { pattern: /your\s+account\s+will\s+be\s+(closed|terminated|deleted)/i, weight: 22, reason: 'Account termination threat' },
        { pattern: /security\s+alert/i, weight: 12, reason: 'Fake security alert' },
        { pattern: /unusual\s+(sign.in|activity|login)/i, weight: 15, reason: 'Fake unusual activity alert' },
        { pattern: /congratulations[!,.]?\s+you('ve|\s+have)?\s+(won|been\s+selected)/i, weight: 30, reason: 'Prize/lottery scam detected' },
        { pattern: /claim\s+your\s+(prize|reward|bonus|gift)/i, weight: 28, reason: 'Fake prize claim' },
        { pattern: /you\s+(have\s+)?won\s+\$?\d/i, weight: 30, reason: 'Fake prize winnings' },
        { pattern: /free\s+(gift\s+card|iphone|samsung|macbook|laptop)/i, weight: 25, reason: 'Free gift scam' },
        { pattern: /limited\s+time\s+offer/i, weight: 8, reason: 'Limited time pressure tactic' },
        { pattern: /act\s+now|don'?t\s+miss\s+out/i, weight: 8, reason: 'Urgency pressure language' },
        { pattern: /make\s+\$?\d+.*per\s+(day|hour|week|month)/i, weight: 20, reason: 'Get-rich-quick scheme' },
        { pattern: /work\s+from\s+home.*\$?\d+/i, weight: 15, reason: 'Suspicious work-from-home offer' },
        { pattern: /enter\s+your\s+(password|credit\s+card|ssn|social\s+security)/i, weight: 25, reason: 'Direct request for sensitive credentials' },
        { pattern: /confirm\s+your\s+(password|billing|payment)/i, weight: 22, reason: 'Credential confirmation request' },
        { pattern: /update\s+your\s+(payment|billing|card)\s+(information|details|method)/i, weight: 20, reason: 'Payment update phishing' },
        { pattern: /(enter|provide|share)\s+your\s+otp/i, weight: 28, reason: 'OTP harvesting attempt' },
        { pattern: /(enter|provide|share)\s+your\s+(bank|account)\s+(details|number|information)/i, weight: 28, reason: 'Bank details harvesting' },
        { pattern: /(cvv|card\s+number|expiry\s+date|expiration)/i, weight: 15, reason: 'Credit card information request' },
        { pattern: /dear\s+(valued\s+)?(customer|user|member|client)/i, weight: 10, reason: 'Generic greeting (impersonation indicator)' },
        { pattern: /customer\s+service\s+team/i, weight: 5, reason: 'Generic customer service claim' },
        { pattern: /tech(nical)?\s+support/i, weight: 8, reason: 'Tech support scam indicator' },
        { pattern: /tax\s+(refund|return|rebate)/i, weight: 18, reason: 'Tax refund scam' },
        { pattern: /(irs|hmrc|income\s+tax)\s+notice/i, weight: 22, reason: 'Fake government tax notice' },
        { pattern: /pending\s+(arrest|legal\s+action|warrant)/i, weight: 25, reason: 'Legal threat scam' },
        { pattern: /click\s+(here|below)\s+to\s+(verify|confirm|update|secure)/i, weight: 18, reason: 'Click-bait social engineering' },
        { pattern: /failure\s+to\s+(respond|comply|verify)/i, weight: 15, reason: 'Compliance threat' },
        { pattern: /within\s+\d+\s+(hours?|minutes?|days?)/i, weight: 10, reason: 'Time pressure tactic' },
        { pattern: /your\s+(computer|device|system)\s+(is|has\s+been)\s+(infected|compromised|hacked)/i, weight: 28, reason: 'Fake infection alert' },
        { pattern: /download\s+(this|the)\s+(antivirus|security|update|patch)/i, weight: 22, reason: 'Fake software download' },
        { pattern: /critical\s+(update|patch|security\s+fix)/i, weight: 15, reason: 'Fake critical update' }
    ];

    const SENSITIVE_FIELD_PATTERNS = {
        password: { types: ['password'], names: /passw(or)?d|pwd|secret/i, placeholders: /password|secret/i, label: 'Password field' },
        creditCard: { types: ['text', 'tel', 'number'], names: /card.?num|cc.?num|credit.?card|debit.?card|card.?no/i, placeholders: /card\s*number|credit\s*card|debit\s*card|\d{4}\s*\d{4}/i, label: 'Credit/Debit card number field' },
        cvv: { types: ['text', 'tel', 'number', 'password'], names: /cvv|cvc|cvn|security.?code|card.?code/i, placeholders: /cvv|cvc|security\s+code/i, label: 'CVV/Security code field' },
        otp: { types: ['text', 'tel', 'number'], names: /otp|one.?time|verification.?code|verify.?code|auth.?code|2fa/i, placeholders: /otp|one.?time|verification|auth\s*code/i, label: 'OTP/Verification code field' },
        bankAccount: { types: ['text', 'tel', 'number'], names: /bank.?acc|account.?num|routing|iban|swift|ifsc|sort.?code/i, placeholders: /bank\s*account|account\s*number|routing|iban|ifsc/i, label: 'Bank account field' },
        ssn: { types: ['text', 'tel', 'number'], names: /ssn|social.?sec|national.?id|aadhaar|pan.?num|id.?num|passport.?num/i, placeholders: /social\s*security|ssn|national\s*id|aadhaar|pan\s*(number|no)/i, label: 'Government ID field' }
    };

    const DANGEROUS_EXTENSIONS = [
        '.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs',
        '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1', '.msp',
        '.cpl', '.hta', '.inf', '.reg', '.rgs', '.sct', '.shb', '.sys',
        '.app', '.action', '.command', '.dmg', '.pkg', '.apk'
    ];

    function getOfficialDomains(brand) {
        const map = {
            'paypal': ['paypal.com'], 'apple': ['apple.com', 'icloud.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazonaws.com'],
            'netflix': ['netflix.com'], 'facebook': ['facebook.com', 'fb.com'],
            'instagram': ['instagram.com'], 'whatsapp': ['whatsapp.com', 'web.whatsapp.com'],
            'twitter': ['twitter.com', 'x.com'], 'linkedin': ['linkedin.com'],
            'chase': ['chase.com'], 'wellsfargo': ['wellsfargo.com'],
            'bankofamerica': ['bankofamerica.com'], 'citibank': ['citibank.com', 'citi.com'],
            'sbi': ['onlinesbi.sbi', 'sbi.co.in'], 'hdfc': ['hdfcbank.com'],
            'icici': ['icicibank.com'], 'paytm': ['paytm.com'],
            'phonepe': ['phonepe.com'], 'gpay': ['pay.google.com']
        };
        return map[brand] || [];
    }

    function analyzeURL(url) {
        const signals = [];
        let score = 0;
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();
            const fullURL = url.toLowerCase();
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')) { score += 30; signals.push('URL uses IP address instead of domain name'); }
            if (urlObj.protocol !== 'https:') { score += 15; signals.push('Site does not use HTTPS encryption'); }
            const tld = '.' + hostname.split('.').pop();
            if (SUSPICIOUS_TLDS.includes(tld)) { score += 15; signals.push('Suspicious top-level domain: ' + tld); }
            const parts = hostname.split('.');
            if (parts.length > 4) { score += 15; signals.push('Excessive subdomains in URL'); }
            for (const brand of IMPERSONATION_TARGETS) {
                const officialDomains = getOfficialDomains(brand);
                const isOfficial = officialDomains.some(function (d) { return hostname === d || hostname.endsWith('.' + d); });
                if (!isOfficial && (hostname.includes(brand) || urlObj.pathname.toLowerCase().includes(brand))) {
                    score += 25; signals.push('Possible impersonation of "' + brand + '"'); break;
                }
            }
            if (fullURL.includes('@') || fullURL.includes('//redirect') || fullURL.includes('//login')) { score += 15; signals.push('Suspicious redirect or authentication bypass in URL'); }
            if (url.length > 200) { score += 8; signals.push('Unusually long URL'); }
            if (/%[0-9a-f]{2}/i.test(hostname)) { score += 15; signals.push('URL encoding in hostname (obfuscation attempt)'); }
            const mainDomain = parts.slice(-2, -1)[0] || '';
            if ((mainDomain.match(/-/g) || []).length >= 3) { score += 12; signals.push('Suspicious hyphen-heavy domain name'); }
            if (urlObj.protocol === 'data:') { score += 35; signals.push('Data URI — content not loaded from a server'); }
        } catch (e) { score += 10; signals.push('Invalid or malformed URL'); }
        return { score: Math.min(score, 100), signals: signals };
    }

    function analyzeContent(text) {
        const signals = [];
        let score = 0;
        const matchedPatterns = new Set();
        if (!text || text.length < 20) return { score: 0, signals: [], matchCount: 0 };
        const normalizedText = text.replace(/\s+/g, ' ').substring(0, 15000);
        for (var i = 0; i < SCAM_PATTERNS.length; i++) {
            var p = SCAM_PATTERNS[i];
            if (p.pattern.test(normalizedText) && !matchedPatterns.has(p.reason)) {
                score += p.weight; signals.push(p.reason); matchedPatterns.add(p.reason);
            }
        }
        return { score: Math.min(score, 80), signals: signals, matchCount: signals.length };
    }

    function detectSensitiveForms(formData) {
        var detectedFields = [];
        if (!formData || !formData.fields) return detectedFields;
        for (var i = 0; i < formData.fields.length; i++) {
            var field = formData.fields[i];
            var entries = Object.entries(SENSITIVE_FIELD_PATTERNS);
            for (var j = 0; j < entries.length; j++) {
                var category = entries[j][0], patterns = entries[j][1];
                var typeMatch = patterns.types.includes(field.type);
                var nameMatch = patterns.names.test(field.name || '') || patterns.names.test(field.id || '');
                var placeholderMatch = patterns.placeholders.test(field.placeholder || '');
                if (typeMatch && (nameMatch || placeholderMatch)) {
                    detectedFields.push({ category: category, label: patterns.label, fieldName: field.name || field.id || 'unnamed', fieldType: field.type });
                    break;
                }
            }
        }
        return detectedFields;
    }

    function isDangerousDownload(url) {
        if (!url) return { dangerous: false };
        var lower = url.toLowerCase();
        for (var i = 0; i < DANGEROUS_EXTENSIONS.length; i++) {
            var ext = DANGEROUS_EXTENSIONS[i];
            if (lower.endsWith(ext) || lower.includes(ext + '?') || lower.includes(ext + '#')) {
                return { dangerous: true, extension: ext, reason: 'Potentially dangerous file type: ' + ext };
            }
        }
        return { dangerous: false };
    }

    function computeRiskScore(urlAnalysis, contentAnalysis, sensitiveFields, isHTTPS) {
        var totalScore = 0;
        totalScore += urlAnalysis.score * 0.4;
        totalScore += contentAnalysis.score * 0.45;
        if (sensitiveFields.length > 0 && (urlAnalysis.score > 20 || contentAnalysis.score > 20)) totalScore += 15;
        if (!isHTTPS && sensitiveFields.length > 0) totalScore += 10;
        return Math.min(Math.round(totalScore), 100);
    }

    function classifyRisk(score) {
        if (score <= 30) return { level: 'safe', label: 'Safe', color: '#00e676' };
        if (score <= 65) return { level: 'suspicious', label: 'Suspicious', color: '#ffd600' };
        return { level: 'dangerous', label: 'Dangerous', color: '#ff1744' };
    }

    function getRecommendation(riskLevel, sensitiveFields) {
        if (riskLevel === 'safe') return 'This website appears safe. Browse normally.';
        if (riskLevel === 'suspicious') {
            if (sensitiveFields.length > 0) return 'This site shows suspicious signs. Avoid entering personal information. Verify the URL carefully before proceeding.';
            return 'This site shows some suspicious indicators. Proceed with caution and avoid sharing sensitive information.';
        }
        if (riskLevel === 'dangerous') return 'This website is likely a phishing or scam site. Leave immediately and do not enter any personal information.';
        return 'Unable to determine risk level.';
    }

    function fullAnalysis(url, pageText, formData) {
        var isHTTPS = url.startsWith('https://');
        var urlResult = analyzeURL(url);
        var contentResult = analyzeContent(pageText);
        var sensitiveFields = detectSensitiveForms(formData);
        var riskScore = computeRiskScore(urlResult, contentResult, sensitiveFields, isHTTPS);
        var classification = classifyRisk(riskScore);
        var allSignals = urlResult.signals.concat(contentResult.signals);
        if (sensitiveFields.length > 0 && riskScore > 30) {
            sensitiveFields.forEach(function (f) { allSignals.push('Sensitive field detected: ' + f.label); });
        }
        var recommendation = getRecommendation(classification.level, sensitiveFields);
        var domain;
        try { domain = new URL(url).hostname; } catch (e) { domain = url; }
        return {
            url: url, domain: domain, isHTTPS: isHTTPS, riskScore: riskScore,
            classification: classification, signals: allSignals, sensitiveFields: sensitiveFields,
            recommendation: recommendation, analyzedAt: new Date().toISOString()
        };
    }

    return {
        analyzeURL: analyzeURL, analyzeContent: analyzeContent,
        detectSensitiveForms: detectSensitiveForms, isDangerousDownload: isDangerousDownload,
        computeRiskScore: computeRiskScore, classifyRisk: classifyRisk,
        getRecommendation: getRecommendation, fullAnalysis: fullAnalysis
    };
})();


// ═══════════════════════════════════════════════
// BACKGROUND SERVICE WORKER LOGIC
// ═══════════════════════════════════════════════

var ICON_PATHS = {
    safe: { 16: 'icons/icon-safe-16.png', 48: 'icons/icon-safe-48.png', 128: 'icons/icon-safe-128.png' },
    suspicious: { 16: 'icons/icon-warning-16.png', 48: 'icons/icon-warning-48.png', 128: 'icons/icon-warning-128.png' },
    dangerous: { 16: 'icons/icon-danger-16.png', 48: 'icons/icon-danger-48.png', 128: 'icons/icon-danger-128.png' }
};

var BADGE_COLORS = { safe: '#00e676', suspicious: '#ffd600', dangerous: '#ff1744' };
var BADGE_TEXT = { safe: '', suspicious: '!', dangerous: '!!' };

async function updateIcon(tabId, riskLevel) {
    try {
        await chrome.action.setIcon({ tabId: tabId, path: ICON_PATHS[riskLevel] || ICON_PATHS.safe });
        await chrome.action.setBadgeText({ tabId: tabId, text: BADGE_TEXT[riskLevel] || '' });
        await chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: BADGE_COLORS[riskLevel] || BADGE_COLORS.safe });
    } catch (e) {
        console.warn('CatchIt: Could not update icon', e);
    }
}

async function storeResults(tabId, results) {
    try {
        var key = 'tab_' + tabId;
        var obj = {};
        obj[key] = results;
        await chrome.storage.session.set(obj);
    } catch (e) {
        console.warn('CatchIt: Could not store results', e);
    }
}

async function getResults(tabId) {
    try {
        var key = 'tab_' + tabId;
        var data = await chrome.storage.session.get(key);
        return data[key] || null;
    } catch (e) {
        return null;
    }
}

// ─── Listen for tab updates ───
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.status !== 'complete' || !tab.url) return;

    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') ||
        tab.url.startsWith('about:') || tab.url.startsWith('edge://')) {
        updateIcon(tabId, 'safe');
        return;
    }

    try {
        chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_PAGE_DATA' }, function (response) {
            if (chrome.runtime.lastError || !response) {
                var urlResult = CatchItAnalyzer.analyzeURL(tab.url);
                var riskScore = Math.min(Math.round(urlResult.score * 0.6), 100);
                var classification = CatchItAnalyzer.classifyRisk(riskScore);
                var domain;
                try { domain = new URL(tab.url).hostname; } catch (e) { domain = tab.url; }

                var results = {
                    url: tab.url, domain: domain, isHTTPS: tab.url.startsWith('https://'),
                    riskScore: riskScore, classification: classification, signals: urlResult.signals,
                    sensitiveFields: [], recommendation: CatchItAnalyzer.getRecommendation(classification.level, []),
                    analyzedAt: new Date().toISOString()
                };

                storeResults(tabId, results);
                updateIcon(tabId, classification.level);
                return;
            }

            var results = CatchItAnalyzer.fullAnalysis(tab.url, response.text || '', response.formData || { fields: [] });
            storeResults(tabId, results);
            updateIcon(tabId, results.classification.level);

            if (results.classification.level !== 'safe') {
                chrome.tabs.sendMessage(tabId, { type: 'SHOW_WARNING', data: results });
            }
        });
    } catch (e) {
        console.error('CatchIt: Analysis error', e);
    }
});

// ─── Message handler ───
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.type === 'GET_RESULTS') {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (!tabs || !tabs[0]) { sendResponse({ error: 'No active tab' }); return; }
            var tab = tabs[0];

            getResults(tab.id).then(function (results) {
                if (results) {
                    sendResponse(results);
                } else {
                    var urlResult = CatchItAnalyzer.analyzeURL(tab.url || '');
                    var riskScore = Math.min(Math.round(urlResult.score * 0.6), 100);
                    var classification = CatchItAnalyzer.classifyRisk(riskScore);
                    var domain;
                    try { domain = new URL(tab.url).hostname; } catch (e) { domain = tab.url; }

                    var quickResults = {
                        url: tab.url, domain: domain, isHTTPS: (tab.url || '').startsWith('https://'),
                        riskScore: riskScore, classification: classification,
                        signals: urlResult.signals.length ? urlResult.signals : ['Initial analysis — full scan pending'],
                        sensitiveFields: [], recommendation: CatchItAnalyzer.getRecommendation(classification.level, []),
                        analyzedAt: new Date().toISOString()
                    };
                    sendResponse(quickResults);
                }
            }).catch(function (e) {
                sendResponse({ error: e.message });
            });
        });
        return true;
    }

    if (message.type === 'PAGE_DATA' && sender.tab) {
        var tabId = sender.tab.id;
        var url = sender.tab.url || message.url || '';
        var results = CatchItAnalyzer.fullAnalysis(url, message.text || '', message.formData || { fields: [] });

        storeResults(tabId, results);
        updateIcon(tabId, results.classification.level);

        if (results.classification.level !== 'safe') {
            chrome.tabs.sendMessage(tabId, { type: 'SHOW_WARNING', data: results });
        }
        sendResponse(results);
        return true;
    }

    if (message.type === 'CHECK_DOWNLOAD') {
        var result = CatchItAnalyzer.isDangerousDownload(message.url);
        sendResponse(result);
        return false;
    }
});

// ─── Clean up when tabs close ───
chrome.tabs.onRemoved.addListener(function (tabId) {
    try {
        var key = 'tab_' + tabId;
        chrome.storage.session.remove(key);
    } catch (e) { /* ignore */ }
});

console.log('CatchIt: Background service worker initialized');
