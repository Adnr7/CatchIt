/**
 * CatchIt AI Analyzer — Local, rule-based threat detection engine
 * Analyzes URLs, page content, and form fields to compute risk scores.
 */

const CatchItAnalyzer = (() => {

  // ─── Suspicious TLD list ───
  const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.club', '.work', '.buzz', '.gq', '.ml', '.cf', '.ga', '.tk',
    '.icu', '.cam', '.rest', '.surf', '.monster', '.quest', '.click', '.link',
    '.support', '.review', '.stream', '.download', '.win', '.bid', '.trade',
    '.racing', '.cricket', '.science', '.party', '.accountant', '.date', '.faith',
    '.loan', '.men', '.zip', '.mov'
  ];

  // ─── Brand impersonation targets ───
  const IMPERSONATION_TARGETS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook',
    'instagram', 'whatsapp', 'twitter', 'linkedin', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'usps', 'fedex', 'dhl', 'ups', 'irs',
    'hmrc', 'gov', 'dropbox', 'adobe', 'yahoo', 'outlook', 'office365',
    'icloud', 'coinbase', 'binance', 'blockchain', 'steam', 'epicgames',
    'roblox', 'telegram', 'discord', 'spotify', 'uber', 'airbnb',
    'sbi', 'hdfc', 'icici', 'paytm', 'phonepe', 'gpay'
  ];

  // ─── Phishing / Scam keyword patterns (weighted) ───
  const SCAM_PATTERNS = [
    // Urgency & Fear
    { pattern: /your\s+account\s+(has\s+been|is)\s+(suspended|locked|compromised|limited)/i, weight: 25, reason: 'Account suspension threat detected' },
    { pattern: /immediate\s+(action|attention)\s+required/i, weight: 20, reason: 'Urgent action pressure tactic' },
    { pattern: /verify\s+your\s+(identity|account|information)/i, weight: 18, reason: 'Identity verification request' },
    { pattern: /unauthorized\s+(access|activity|transaction)/i, weight: 20, reason: 'Unauthorized activity scare tactic' },
    { pattern: /your\s+account\s+will\s+be\s+(closed|terminated|deleted)/i, weight: 22, reason: 'Account termination threat' },
    { pattern: /security\s+alert/i, weight: 12, reason: 'Fake security alert' },
    { pattern: /unusual\s+(sign.in|activity|login)/i, weight: 15, reason: 'Fake unusual activity alert' },

    // Financial Scams
    { pattern: /congratulations[!,.]?\s+you('ve|\s+have)?\s+(won|been\s+selected)/i, weight: 30, reason: 'Prize/lottery scam detected' },
    { pattern: /claim\s+your\s+(prize|reward|bonus|gift)/i, weight: 28, reason: 'Fake prize claim' },
    { pattern: /you\s+(have\s+)?won\s+\$?\d/i, weight: 30, reason: 'Fake prize winnings' },
    { pattern: /free\s+(gift\s+card|iphone|samsung|macbook|laptop)/i, weight: 25, reason: 'Free gift scam' },
    { pattern: /limited\s+time\s+offer/i, weight: 8, reason: 'Limited time pressure tactic' },
    { pattern: /act\s+now|don'?t\s+miss\s+out/i, weight: 8, reason: 'Urgency pressure language' },
    { pattern: /make\s+\$?\d+.*per\s+(day|hour|week|month)/i, weight: 20, reason: 'Get-rich-quick scheme' },
    { pattern: /work\s+from\s+home.*\$?\d+/i, weight: 15, reason: 'Suspicious work-from-home offer' },

    // Credential Harvesting
    { pattern: /enter\s+your\s+(password|credit\s+card|ssn|social\s+security)/i, weight: 25, reason: 'Direct request for sensitive credentials' },
    { pattern: /confirm\s+your\s+(password|billing|payment)/i, weight: 22, reason: 'Credential confirmation request' },
    { pattern: /update\s+your\s+(payment|billing|card)\s+(information|details|method)/i, weight: 20, reason: 'Payment update phishing' },
    { pattern: /(enter|provide|share)\s+your\s+otp/i, weight: 28, reason: 'OTP harvesting attempt' },
    { pattern: /(enter|provide|share)\s+your\s+(bank|account)\s+(details|number|information)/i, weight: 28, reason: 'Bank details harvesting' },
    { pattern: /(cvv|card\s+number|expiry\s+date|expiration)/i, weight: 15, reason: 'Credit card information request' },

    // Impersonation
    { pattern: /dear\s+(valued\s+)?(customer|user|member|client)/i, weight: 10, reason: 'Generic greeting (impersonation indicator)' },
    { pattern: /customer\s+service\s+team/i, weight: 5, reason: 'Generic customer service claim' },
    { pattern: /tech(nical)?\s+support/i, weight: 8, reason: 'Tech support scam indicator' },

    // Government / Tax Scams
    { pattern: /tax\s+(refund|return|rebate)/i, weight: 18, reason: 'Tax refund scam' },
    { pattern: /(irs|hmrc|income\s+tax)\s+notice/i, weight: 22, reason: 'Fake government tax notice' },
    { pattern: /pending\s+(arrest|legal\s+action|warrant)/i, weight: 25, reason: 'Legal threat scam' },

    // Social Engineering
    { pattern: /click\s+(here|below)\s+to\s+(verify|confirm|update|secure)/i, weight: 18, reason: 'Click-bait social engineering' },
    { pattern: /failure\s+to\s+(respond|comply|verify)/i, weight: 15, reason: 'Compliance threat' },
    { pattern: /within\s+\d+\s+(hours?|minutes?|days?)/i, weight: 10, reason: 'Time pressure tactic' },

    // Malware / Downloads
    { pattern: /your\s+(computer|device|system)\s+(is|has\s+been)\s+(infected|compromised|hacked)/i, weight: 28, reason: 'Fake infection alert' },
    { pattern: /download\s+(this|the)\s+(antivirus|security|update|patch)/i, weight: 22, reason: 'Fake software download' },
    { pattern: /critical\s+(update|patch|security\s+fix)/i, weight: 15, reason: 'Fake critical update' }
  ];

  // ─── Sensitive form field patterns ───
  const SENSITIVE_FIELD_PATTERNS = {
    password: {
      types: ['password'],
      names: /passw(or)?d|pwd|secret/i,
      placeholders: /password|secret/i,
      label: 'Password field'
    },
    creditCard: {
      types: ['text', 'tel', 'number'],
      names: /card.?num|cc.?num|credit.?card|debit.?card|card.?no/i,
      placeholders: /card\s*number|credit\s*card|debit\s*card|\d{4}\s*\d{4}/i,
      label: 'Credit/Debit card number field'
    },
    cvv: {
      types: ['text', 'tel', 'number', 'password'],
      names: /cvv|cvc|cvn|security.?code|card.?code/i,
      placeholders: /cvv|cvc|security\s+code/i,
      label: 'CVV/Security code field'
    },
    otp: {
      types: ['text', 'tel', 'number'],
      names: /otp|one.?time|verification.?code|verify.?code|auth.?code|2fa/i,
      placeholders: /otp|one.?time|verification|auth\s*code/i,
      label: 'OTP/Verification code field'
    },
    bankAccount: {
      types: ['text', 'tel', 'number'],
      names: /bank.?acc|account.?num|routing|iban|swift|ifsc|sort.?code/i,
      placeholders: /bank\s*account|account\s*number|routing|iban|ifsc/i,
      label: 'Bank account field'
    },
    ssn: {
      types: ['text', 'tel', 'number'],
      names: /ssn|social.?sec|national.?id|aadhaar|pan.?num|id.?num|passport.?num/i,
      placeholders: /social\s*security|ssn|national\s*id|aadhaar|pan\s*(number|no)/i,
      label: 'Government ID field'
    }
  };

  // ─── Dangerous file extensions ───
  const DANGEROUS_EXTENSIONS = [
    '.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs',
    '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1', '.msp',
    '.cpl', '.hta', '.inf', '.reg', '.rgs', '.sct', '.shb', '.sys',
    '.app', '.action', '.command', '.dmg', '.pkg', '.apk'
  ];

  /**
   * Analyze URL for suspicious characteristics
   */
  function analyzeURL(url) {
    const signals = [];
    let score = 0;

    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const fullURL = url.toLowerCase();

      // 1. IP address instead of domain
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')) {
        score += 30;
        signals.push('URL uses IP address instead of domain name');
      }

      // 2. No HTTPS
      if (urlObj.protocol !== 'https:') {
        score += 15;
        signals.push('Site does not use HTTPS encryption');
      }

      // 3. Suspicious TLD
      const tld = '.' + hostname.split('.').pop();
      if (SUSPICIOUS_TLDS.includes(tld)) {
        score += 15;
        signals.push(`Suspicious top-level domain: ${tld}`);
      }

      // 4. Excessive subdomains
      const parts = hostname.split('.');
      if (parts.length > 4) {
        score += 15;
        signals.push('Excessive subdomains in URL');
      }

      // 5. Brand impersonation in subdomain or path
      for (const brand of IMPERSONATION_TARGETS) {
        const officialDomains = getOfficialDomains(brand);
        const isOfficial = officialDomains.some(d => hostname === d || hostname.endsWith('.' + d));

        if (!isOfficial && (hostname.includes(brand) || urlObj.pathname.toLowerCase().includes(brand))) {
          score += 25;
          signals.push(`Possible impersonation of "${brand}"`);
          break;
        }
      }

      // 6. Suspicious characters in URL
      if (fullURL.includes('@') || fullURL.includes('//redirect') || fullURL.includes('//login')) {
        score += 15;
        signals.push('Suspicious redirect or authentication bypass in URL');
      }

      // 7. Very long URL
      if (url.length > 200) {
        score += 8;
        signals.push('Unusually long URL');
      }

      // 8. Encoded characters in hostname
      if (/%[0-9a-f]{2}/i.test(hostname)) {
        score += 15;
        signals.push('URL encoding in hostname (obfuscation attempt)');
      }

      // 9. Hyphen-heavy domain
      const mainDomain = parts.slice(-2, -1)[0] || '';
      if ((mainDomain.match(/-/g) || []).length >= 3) {
        score += 12;
        signals.push('Suspicious hyphen-heavy domain name');
      }

      // 10. Data URI
      if (urlObj.protocol === 'data:') {
        score += 35;
        signals.push('Data URI — content not loaded from a server');
      }

    } catch (e) {
      score += 10;
      signals.push('Invalid or malformed URL');
    }

    return { score: Math.min(score, 100), signals };
  }

  /**
   * Get official domain list for a brand
   */
  function getOfficialDomains(brand) {
    const map = {
      'paypal': ['paypal.com'],
      'apple': ['apple.com', 'icloud.com'],
      'google': ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com'],
      'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'],
      'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazonaws.com'],
      'netflix': ['netflix.com'],
      'facebook': ['facebook.com', 'fb.com'],
      'instagram': ['instagram.com'],
      'whatsapp': ['whatsapp.com', 'web.whatsapp.com'],
      'twitter': ['twitter.com', 'x.com'],
      'linkedin': ['linkedin.com'],
      'chase': ['chase.com'],
      'wellsfargo': ['wellsfargo.com'],
      'bankofamerica': ['bankofamerica.com'],
      'citibank': ['citibank.com', 'citi.com'],
      'sbi': ['onlinesbi.sbi', 'sbi.co.in'],
      'hdfc': ['hdfcbank.com'],
      'icici': ['icicibank.com'],
      'paytm': ['paytm.com'],
      'phonepe': ['phonepe.com'],
      'gpay': ['pay.google.com']
    };
    return map[brand] || [];
  }

  /**
   * Analyze page content for scam/phishing indicators
   */
  function analyzeContent(text) {
    const signals = [];
    let score = 0;
    const matchedPatterns = new Set();

    if (!text || text.length < 20) {
      return { score: 0, signals: [], matchCount: 0 };
    }

    // Normalize text
    const normalizedText = text.replace(/\s+/g, ' ').substring(0, 15000);

    for (const { pattern, weight, reason } of SCAM_PATTERNS) {
      if (pattern.test(normalizedText) && !matchedPatterns.has(reason)) {
        score += weight;
        signals.push(reason);
        matchedPatterns.add(reason);
      }
    }

    // Cap content score
    score = Math.min(score, 80);

    return { score, signals, matchCount: signals.length };
  }

  /**
   * Detect sensitive form fields
   */
  function detectSensitiveForms(formData) {
    const detectedFields = [];

    if (!formData || !formData.fields) return detectedFields;

    for (const field of formData.fields) {
      for (const [category, patterns] of Object.entries(SENSITIVE_FIELD_PATTERNS)) {
        const typeMatch = patterns.types.includes(field.type);
        const nameMatch = patterns.names.test(field.name || '') || patterns.names.test(field.id || '');
        const placeholderMatch = patterns.placeholders.test(field.placeholder || '');
        const autocompleteMatch = field.autocomplete && /cc-|credit|password|username/i.test(field.autocomplete);

        if (typeMatch && (nameMatch || placeholderMatch || autocompleteMatch)) {
          detectedFields.push({
            category,
            label: patterns.label,
            fieldName: field.name || field.id || 'unnamed',
            fieldType: field.type
          });
          break;
        }
      }
    }

    return detectedFields;
  }

  /**
   * Check if a URL points to a dangerous download
   */
  function isDangerousDownload(url) {
    if (!url) return { dangerous: false };
    const lower = url.toLowerCase();
    for (const ext of DANGEROUS_EXTENSIONS) {
      if (lower.endsWith(ext) || lower.includes(ext + '?') || lower.includes(ext + '#')) {
        return { dangerous: true, extension: ext, reason: `Potentially dangerous file type: ${ext}` };
      }
    }
    return { dangerous: false };
  }

  /**
   * Compute final risk score combining all signals
   */
  function computeRiskScore(urlAnalysis, contentAnalysis, sensitiveFields, isHTTPS) {
    let totalScore = 0;

    // URL analysis weight: 40%
    totalScore += urlAnalysis.score * 0.4;

    // Content analysis weight: 45%
    totalScore += contentAnalysis.score * 0.45;

    // Sensitive forms on suspicious site: +15
    if (sensitiveFields.length > 0 && (urlAnalysis.score > 20 || contentAnalysis.score > 20)) {
      totalScore += 15;
    }

    // No HTTPS with sensitive forms: +10
    if (!isHTTPS && sensitiveFields.length > 0) {
      totalScore += 10;
    }

    return Math.min(Math.round(totalScore), 100);
  }

  /**
   * Classify risk level from score
   */
  function classifyRisk(score) {
    if (score <= 30) return { level: 'safe', label: 'Safe', color: '#00e676' };
    if (score <= 65) return { level: 'suspicious', label: 'Suspicious', color: '#ffd600' };
    return { level: 'dangerous', label: 'Dangerous', color: '#ff1744' };
  }

  /**
   * Get recommended action based on risk level
   */
  function getRecommendation(riskLevel, sensitiveFields) {
    switch (riskLevel) {
      case 'safe':
        return 'This website appears safe. Browse normally.';
      case 'suspicious':
        if (sensitiveFields.length > 0) {
          return 'This site shows suspicious signs. Avoid entering personal information. Verify the URL carefully before proceeding.';
        }
        return 'This site shows some suspicious indicators. Proceed with caution and avoid sharing sensitive information.';
      case 'dangerous':
        return 'This website is likely a phishing or scam site. Leave immediately and do not enter any personal information.';
      default:
        return 'Unable to determine risk level.';
    }
  }

  /**
   * Run full analysis
   */
  function fullAnalysis(url, pageText, formData) {
    const isHTTPS = url.startsWith('https://');
    const urlResult = analyzeURL(url);
    const contentResult = analyzeContent(pageText);
    const sensitiveFields = detectSensitiveForms(formData);
    const riskScore = computeRiskScore(urlResult, contentResult, sensitiveFields, isHTTPS);
    const classification = classifyRisk(riskScore);
    const allSignals = [...urlResult.signals, ...contentResult.signals];

    if (sensitiveFields.length > 0 && riskScore > 30) {
      sensitiveFields.forEach(f => allSignals.push(`Sensitive field detected: ${f.label}`));
    }

    const recommendation = getRecommendation(classification.level, sensitiveFields);

    return {
      url,
      domain: (() => { try { return new URL(url).hostname; } catch (e) { return url; } })(),
      isHTTPS,
      riskScore,
      classification,
      signals: allSignals,
      sensitiveFields,
      recommendation,
      analyzedAt: new Date().toISOString()
    };
  }

  return {
    analyzeURL,
    analyzeContent,
    detectSensitiveForms,
    isDangerousDownload,
    computeRiskScore,
    classifyRisk,
    getRecommendation,
    fullAnalysis,
    DANGEROUS_EXTENSIONS
  };

})();

// Make available in both content script and module contexts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CatchItAnalyzer;
}
