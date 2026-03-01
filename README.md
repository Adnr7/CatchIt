<p align="center">
  <img src="icons/icon-safe-128.png" alt="CatchIt Logo" width="80"/>
</p>

<h1 align="center">CatchIt — AI Safe Browsing</h1>

<p align="center">
  <strong>AI-powered Chrome extension that protects you from phishing, scams, and malicious websites in real time.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/manifest-v3-brightgreen?style=flat-square" alt="Manifest V3"/>
  <img src="https://img.shields.io/badge/AI-local--only-00e676?style=flat-square" alt="Local AI"/>
  <img src="https://img.shields.io/badge/privacy-100%25-blueviolet?style=flat-square" alt="Privacy"/>
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version"/>
</p>

---

## 🚀 What is CatchIt?

CatchIt is a browser extension that uses **intelligent pattern recognition and NLP-based content analysis** to detect phishing, scam, and malicious websites — including **zero-day threats** that traditional blacklist tools miss.

It runs silently on every page you visit, assigns a **risk score (0–100)**, and actively prevents you from submitting sensitive data on dangerous sites.

### ✨ Key Highlights

- 🧠 **AI-Powered** — 30+ NLP patterns detect scams, phishing, and social engineering
- 🔒 **100% Private** — All analysis runs locally, zero data sent to any server
- ⚡ **Real-Time** — Analyzes every page in under 50ms
- 🛡️ **Proactive Protection** — Blocks form submissions and dangerous downloads on risky sites

---

## 🎯 Features

| Feature | Description |
|---|---|
| **Risk Scoring** | Assigns 0–100 score with Safe / Suspicious / Dangerous classification |
| **URL Analysis** | Detects suspicious TLDs, IP-based URLs, brand impersonation, encoding tricks |
| **Content NLP** | Identifies urgency threats, fake prizes, credential harvesting, malware alerts |
| **Form Protection** | Blocks password, credit card, OTP, bank details on risky sites |
| **Download Guard** | Warns before downloading `.exe`, `.bat`, `.apk`, `.scr` and 20+ dangerous types |
| **Visual Alerts** | Color-coded shield icon (🟢🟡🔴) + animated warning banners on pages |
| **Dashboard** | One-click popup with risk ring, signals, site info, and recommendations |

---

## 📸 How It Works

```
User visits webpage
        │
        ▼
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Content Script  │────▶│  Background      │◀────│  Popup UI    │
│  • Extract text  │     │  Service Worker   │     │  • Risk ring │
│  • Scan forms    │     │  • AI Analyzer    │     │  • Signals   │
│  • Inject alerts │◀────│  • Score & cache  │────▶│  • Actions   │
└─────────────────┘     └──────────────────┘     └──────────────┘
```

### Scoring Breakdown

| Signal | Weight |
|---|---|
| URL Analysis (TLD, IP, impersonation, encoding) | 40% |
| Content NLP (30+ scam/phishing patterns) | 45% |
| Sensitive forms on suspicious site | +15 bonus |

| Score | Classification |
|---|---|
| 0 – 30 | 🟢 **Safe** |
| 31 – 65 | 🟡 **Suspicious** |
| 66 – 100 | 🔴 **Dangerous** |

---

## 🔧 Installation

1. **Download** this repository or clone it:
   ```bash
   git clone https://github.com/Adnr7/CatchIt.git
   ```

2. Open **Chrome** and go to `chrome://extensions`

3. Enable **Developer mode** (toggle in top-right)

4. Click **"Load unpacked"** and select the `CatchIt` folder

5. ✅ The green shield icon appears in your toolbar — you're protected!

---

## 📁 Project Structure

```
CatchIt/
├── manifest.json       # Extension configuration (Manifest V3)
├── background.js       # Service worker + inlined AI analyzer
├── ai-analyzer.js      # AI engine (URL + NLP + form detection)
├── content.js          # Page scanner, warning banners, form guards
├── content.css         # Injected banner & overlay styles
├── popup.html          # Dashboard popup structure
├── popup.js            # Dashboard logic & rendering
├── popup.css           # Dashboard styles (glassmorphic dark theme)
└── icons/              # Shield icons (9 PNGs: 3 states × 3 sizes)
    ├── icon-safe-*.png
    ├── icon-warning-*.png
    └── icon-danger-*.png
```

---

## 🛡️ What It Detects

### URL Threats
- IP-based URLs instead of domain names
- Missing HTTPS encryption
- Suspicious TLDs (`.xyz`, `.tk`, `.buzz`, `.zip`, etc.)
- Brand impersonation (`paypa1.com`, `amaz0n-login.com`)
- URL encoding tricks and excessive subdomains

### Content Threats (NLP)
- Account suspension/termination threats
- Fake prize and lottery scams
- Credential harvesting ("enter your password/OTP/SSN")
- Government/tax impersonation
- Fake malware/virus alerts
- Urgency and fear tactics

### Form Threats
- Password fields on suspicious sites
- Credit card / debit card number inputs
- OTP / verification code fields
- Bank account / IFSC / routing number fields
- SSN / Aadhaar / PAN / passport number fields

---

## 🔐 Privacy

CatchIt is **100% local**. No browsing data, page content, or analysis results are ever sent to any external server. All AI processing happens on your device using JavaScript pattern matching.

---

## 🛠️ Tech Stack

- **Chrome Extension Manifest V3**
- **JavaScript (ES6+)** — Core logic
- **NLP Pattern Matching** — 30+ weighted regex rules
- **Chrome APIs** — Tabs, Storage, Action, Scripting, Runtime
- **HTML5 + CSS3** — Glassmorphic UI with animations
- **Canvas API** — Programmatic icon generation

---

## 👥 Target Users

- General internet users
- Students and young users
- Online shoppers
- Elderly users vulnerable to scams
- Remote workers and small business employees

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

<p align="center">
  Built with 🛡️ for <strong>AMD Slingshot Hackathon</strong>
</p>
