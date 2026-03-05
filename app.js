/**
 * PhishGuard AI - Core Logic (Improved Detection Engine)
 */

const SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy'
];

const SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'click', 'download', 'date', 'racing', 'win', 'bid', 'stream'];

// Keywords frequently used in URL-based social engineering
const SUSPICIOUS_KEYWORDS = [
    'verify', 'verification', 'secure', 'security', 'account',
    'update', 'confirm', 'banking', 'login', 'signin', 'log-in',
    'support', 'billing', 'payment', 'authentication', 'validate',
    'recover', 'alert', 'suspended', 'unlock', 'restore'
];

// Legitimate brands often impersonated in phishing subdomains
const BRAND_NAMES = [
    'amazon', 'paypal', 'apple', 'google', 'microsoft',
    'facebook', 'instagram', 'netflix', 'ebay', 'dropbox',
    'twitter', 'linkedin', 'bank', 'chase', 'wellsfargo',
    'citibank', 'irs', 'fedex', 'dhl', 'ups'
];

function extractFeatures(url) {
    let parsed;
    try {
        parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    } catch (e) {
        return null;
    }

    const domain = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    const fullUrl = url.toLowerCase();
    const parts = domain.split('.');
    const registeredDomain = parts.slice(-2).join('.'); // e.g., security-check.com
    const subdomains = parts.slice(0, -2).join('.');    // e.g., amazon.login.verify-account

    // Count suspicious keywords in the entire URL
    const keywordsFound = SUSPICIOUS_KEYWORDS.filter(k => fullUrl.includes(k));

    // Detect brand names in subdomain (impersonation)
    const brandsFound = BRAND_NAMES.filter(b => subdomains.includes(b));

    // Hyphens in the registered domain (e.g., security-check.com)
    const hyphensInDomain = (registeredDomain.match(/-/g) || []).length;

    return {
        url_length: url.length,
        has_ip: /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) ? 1 : 0,
        has_at_sign: url.includes('@') ? 1 : 0,
        has_shortener: SHORTENING_SERVICES.some(s => domain.includes(s)) ? 1 : 0,
        suspicious_tld: SUSPICIOUS_TLDS.some(t => domain.endsWith('.' + t)) ? 1 : 0,
        no_https: parsed.protocol !== 'https:' ? 1 : 0,
        subdomain_count: Math.max(0, parts.length - 2),
        path_length: path.length,
        suspicious_keyword_count: keywordsFound.length,
        brand_impersonation: brandsFound.length > 0 ? 1 : 0,
        hyphens_in_domain: hyphensInDomain,
        keywords_found: keywordsFound,
        brands_found: brandsFound,
        registered_domain: registeredDomain
    };
}

function analyzeRisk(f) {
    if (!f) return null;
    let score = 0;

    // High confidence indicators
    if (f.has_ip) score += 40;
    if (f.has_at_sign) score += 30;
    if (f.brand_impersonation) score += 35; // e.g., amazon.login.security-check.com
    if (f.has_shortener) score += 25;
    if (f.suspicious_tld) score += 20;
    if (f.no_https) score += 15;

    // Suspicious keywords (e.g., verify-account, secure-update)
    score += Math.min(f.suspicious_keyword_count * 12, 36);

    // Subdomain depth (e.g., a.b.c.evil.com)
    if (f.subdomain_count > 2) score += 20;
    else if (f.subdomain_count > 1) score += 10;

    // Hyphens in the main domain (e.g., security-check.com, paypal-verify.com)
    if (f.hyphens_in_domain > 1) score += 20;
    else if (f.hyphens_in_domain === 1) score += 10;

    // URL length
    if (f.url_length > 100) score += 10;
    else if (f.url_length > 75) score += 5;

    score = Math.min(score, 100);
    return {
        score,
        level: score > 50 ? 'Danger' : (score > 20 ? 'Warning' : 'Safe'),
        confidence: Math.min(95, 80 + score / 10)
    };
}

// UI Handling
document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const resultArea = document.getElementById('result-area');

    scanBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (!url) return;

        scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        scanBtn.disabled = true;

        setTimeout(() => {
            const features = extractFeatures(url);
            const risk = analyzeRisk(features);

            if (risk) {
                renderResult(risk, features);
            } else {
                alert('Please enter a valid URL.');
            }

            scanBtn.innerHTML = 'Scan Now <i class="fas fa-arrow-right"></i>';
            scanBtn.disabled = false;
        }, 1200);
    });

    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') scanBtn.click();
    });

    function renderResult(risk, f) {
        resultArea.style.display = 'block';
        const isSafe = risk.level === 'Safe';
        const isWarn = risk.level === 'Warning';
        const color = isSafe ? '#00ff41' : (isWarn ? '#ff8c00' : '#ff4b2b');
        const tagClass = isSafe ? 'safe-tag' : 'danger-tag';
        const headline = isSafe ? 'Link appears safe' : (isWarn ? 'Suspicious Link Detected' : 'Phishing Link Detected');

        resultArea.innerHTML = `
            <div class="result-header">
                <div>
                    <h3 style="color: ${color}; margin-bottom: 4px;">${headline}</h3>
                    <p style="font-size: 0.85rem; color: var(--text-secondary)">Risk Score: ${risk.score}/100 &nbsp;|&nbsp; AI Confidence: ${risk.confidence.toFixed(1)}%</p>
                </div>
                <span class="risk-tag ${tagClass}">${risk.level}</span>
            </div>

            <div class="risk-bar">
                <div class="risk-level" style="width: ${risk.score}%; background: ${color}; box-shadow: 0 0 10px ${color}"></div>
            </div>

            <div class="analysis-report">
                <h4 style="font-size: 0.9rem; margin-bottom: 1rem; color: var(--text-primary)">Analysis Details:</h4>
                <ul style="list-style: none; font-size: 0.9rem;">
                    ${generateReportItems(f, risk)}
                </ul>
            </div>
        `;
        resultArea.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function generateReportItems(f, r) {
        let items = [];

        if (f.brand_impersonation) {
            items.push(`<li><span style="color:#ff4b2b"><i class="fas fa-exclamation-circle"></i> Brand impersonation detected: "<strong>${f.brands_found.join(', ')}</strong>" used in subdomain to appear legitimate, but the real domain is <strong>${f.registered_domain}</strong>.</span></li>`);
        }
        if (f.has_ip) {
            items.push('<li><span style="color:#ff4b2b"><i class="fas fa-exclamation-circle"></i> Uses an IP address instead of a domain name — a common phishing tactic.</span></li>');
        }
        if (f.has_at_sign) {
            items.push('<li><span style="color:#ff4b2b"><i class="fas fa-exclamation-circle"></i> Contains "@" symbol used for URL masking.</span></li>');
        }
        if (f.suspicious_keyword_count > 0) {
            items.push(`<li><span style="color:#ff8c00"><i class="fas fa-info-circle"></i> Suspicious keywords found: <strong>${f.keywords_found.join(', ')}</strong>. These are commonly used to create a false sense of urgency.</span></li>`);
        }
        if (f.hyphens_in_domain > 0) {
            items.push(`<li><span style="color:#ff8c00"><i class="fas fa-info-circle"></i> The main domain uses hyphens (<strong>${f.registered_domain}</strong>), a tactic often used to mimic legitimate sites.</span></li>`);
        }
        if (f.subdomain_count > 1) {
            items.push(`<li><span style="color:#ff8c00"><i class="fas fa-info-circle"></i> Unusually deep subdomain structure (${f.subdomain_count} levels) — used to bury fake context before the real domain.</span></li>`);
        }
        if (f.has_shortener) {
            items.push('<li><span style="color:#ff8c00"><i class="fas fa-info-circle"></i> Link is hidden behind a URL shortening service.</span></li>');
        }
        if (f.suspicious_tld) {
            items.push('<li><span style="color:#ff8c00"><i class="fas fa-info-circle"></i> Top-level domain frequently associated with phishing sites.</span></li>');
        }
        if (f.no_https) {
            items.push('<li><span style="color:#ff8c00"><i class="fas fa-lock-open"></i> Connection is not encrypted (no HTTPS).</span></li>');
        }

        if (items.length === 0) {
            items.push('<li><span style="color:#00ff41"><i class="fas fa-check-circle"></i> No suspicious structural patterns detected by AI.</span></li>');
        }

        return items.map(i => `<li style="margin-bottom: 12px; display: flex; gap: 10px; align-items: start;">${i}</li>`).join('');
    }
});
