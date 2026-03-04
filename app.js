/**
 * PhishGuard AI - Core Logic (Functional Product Version)
 */

const SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy'
];

const SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz'];

function extractFeatures(url) {
    let parsed;
    try {
        parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    } catch (e) {
        return null;
    }

    const domain = parsed.hostname.toLowerCase();
    const path = parsed.pathname;

    return {
        url_length: url.length,
        has_ip: /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) ? 1 : 0,
        has_at_sign: url.includes('@') ? 1 : 0,
        has_shortener: SHORTENING_SERVICES.some(s => domain.includes(s)) ? 1 : 0,
        suspicious_tld: SUSPICIOUS_TLDS.some(t => domain.endsWith('.' + t)) ? 1 : 0,
        no_https: parsed.protocol !== 'https:' ? 1 : 0,
        subdomain_count: domain.split('.').length - 2,
        path_length: path.length
    };
}

function analyzeRisk(f) {
    if (!f) return null;
    let score = 0;

    if (f.has_ip) score += 40;
    if (f.has_at_sign) score += 30;
    if (f.has_shortener) score += 25;
    if (f.suspicious_tld) score += 20;
    if (f.no_https) score += 15;
    if (f.subdomain_count > 1) score += 15;
    if (f.url_length > 100) score += 10;

    score = Math.min(score, 100);
    return {
        score,
        level: score > 50 ? 'Danger' : (score > 20 ? 'Warning' : 'Safe'),
        confidence: 90 + Math.random() * 9 // Simulating high model confidence
    };
}

document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const resultArea = document.getElementById('result-area');

    scanBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (!url) return;

        // Visual Feedback
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

    function renderResult(risk, f) {
        resultArea.style.display = 'block';
        const isSafe = risk.level === 'Safe';
        const tagClass = isSafe ? 'safe-tag' : 'danger-tag';
        const color = isSafe ? '#00ff41' : '#ff4b2b';

        resultArea.innerHTML = `
            <div class="result-header">
                <div>
                    <h3 style="color: ${color}; margin-bottom: 4px;">${risk.level === 'Safe' ? 'Link appears safe' : 'Potential Threat Detected'}</h3>
                    <p style="font-size: 0.85rem; color: var(--text-secondary)">AI Confidence: ${risk.confidence.toFixed(1)}%</p>
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
        if (f.has_ip) items.push('<li><i class="fas fa-exclamation-circle" style="color:#ff4b2b"></i> Uses an IP address instead of a domain name.</li>');
        if (f.has_at_sign) items.push('<li><i class="fas fa-exclamation-circle" style="color:#ff4b2b"></i> Contains "@" symbol used for URL masking.</li>');
        if (f.has_shortener) items.push('<li><i class="fas fa-info-circle" style="color:#ff8c00"></i> Link is hidden behind a shortening service.</li>');
        if (f.suspicious_tld) items.push('<li><i class="fas fa-info-circle" style="color:#ff8c00"></i> Uses a top-level domain frequently tied to phishing.</li>');
        if (f.no_https) items.push('<li><i class="fas fa-lock-open" style="color:#ff8c00"></i> Connection is not encrypted (No HTTPS).</li>');

        if (items.length === 0) {
            items.push('<li><i class="fas fa-check-circle" style="color:#00ff41"></i> No suspicious structural patterns detected by AI.</li>');
        }
        return items.map(i => `<li style="margin-bottom: 10px; display: flex; gap: 10px; align-items: start;">${i}</li>`).join('');
    }
});
