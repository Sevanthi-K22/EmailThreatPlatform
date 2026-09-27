/**
 * ===========================================================
 * DOMAIN INTELLIGENCE & DNS RECORD AUDIT ENGINE
 * ===========================================================
 *
 * Implements:
 * 1. Live DNS Records Audit (MX, A, TXT, NS) via dns.promises
 * 2. Missing MX Record Detection (Critical sender anomaly)
 * 3. High-Risk TLD Classifier (.xyz, .top, .icu, etc.)
 * 4. Brand Typosquatting & Homoglyph Lookalike Detection
 * 5. Composite Domain Risk Scoring
 * ===========================================================
 */

const dns = require("dns").promises;

// High-risk TLDs frequently abused in phishing/BEC
const HIGH_RISK_TLDS = new Set([
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "icu", "cam",
    "work", "click", "rest", "country", "stream", "live", "guru", "fit", "surf"
]);

// Protected high-value enterprise brands frequently targeted
const PROTECTED_BRANDS = [
    { brand: "Microsoft", domains: ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"] },
    { brand: "PayPal", domains: ["paypal.com", "paypal-communication.com"] },
    { brand: "Google", domains: ["google.com", "gmail.com"] },
    { brand: "Apple", domains: ["apple.com", "icloud.com"] },
    { brand: "Amazon", domains: ["amazon.com", "aws.amazon.com"] },
    { brand: "Netflix", domains: ["netflix.com"] },
    { brand: "Chase Bank", domains: ["chase.com"] },
    { brand: "Bank of America", domains: ["bankofamerica.com", "bofa.com"] },
    { brand: "Wells Fargo", domains: ["wellsfargo.com"] },
    { brand: "DHL", domains: ["dhl.com"] },
    { brand: "FedEx", domains: ["fedex.com"] },
    { brand: "DocuSign", domains: ["docusign.com"] }
];

/**
 * Levenshtein Distance algorithm for typosquatting calculation
 */
function levenshteinDistance(s1, s2) {
    const len1 = s1.length;
    const len2 = s2.length;
    const matrix = Array.from({ length: len1 + 1 }, () => Array(len2 + 1).fill(0));

    for (let i = 0; i <= len1; i++) matrix[i][0] = i;
    for (let j = 0; j <= len2; j++) matrix[0][j] = j;

    for (let i = 1; i <= len1; i++) {
        for (let j = 1; j <= len2; j++) {
            const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,       // deletion
                matrix[i][j - 1] + 1,       // insertion
                matrix[i - 1][j - 1] + cost // substitution
            );
        }
    }
    return matrix[len1][len2];
}

/**
 * Normalize homoglyphs and leetspeak numbers
 */
function normalizeHomoglyphs(str) {
    return str
        .replace(/0/g, "o")
        .replace(/1/g, "l")
        .replace(/3/g, "e")
        .replace(/4/g, "a")
        .replace(/5/g, "s")
        .replace(/vv/g, "w")
        .replace(/rn/g, "m");
}

/**
 * Detect brand impersonation and typosquatting in a domain
 */
function detectTyposquatting(domain) {
    const clean = String(domain || "").trim().toLowerCase();
    if (!clean || !clean.includes(".")) return { isLookalike: false };

    const domainName = clean.split(".")[0];
    const normalizedName = normalizeHomoglyphs(domainName);

    for (const item of PROTECTED_BRANDS) {
        for (const brandDomain of item.domains) {
            const brandName = brandDomain.split(".")[0];

            // Direct legitimate match
            if (clean === brandDomain || clean.endsWith("." + brandDomain)) {
                return { isLookalike: false, isLegitimate: true, brand: item.brand };
            }

            // Keyword inclusion in domain (e.g., "paypal-security-update.com", "microsoft-login-auth.com")
            if (domainName.includes(brandName) || normalizedName.includes(brandName)) {
                return {
                    isLookalike: true,
                    targetBrand: item.brand,
                    targetDomain: brandDomain,
                    method: "Brand Name Keyword Injection",
                    distance: 0
                };
            }

            // Edit distance typosquatting (e.g., "micros0ft", "paypa1")
            const dist = levenshteinDistance(domainName, brandName);
            if (dist > 0 && dist <= 2 && Math.abs(domainName.length - brandName.length) <= 2) {
                return {
                    isLookalike: true,
                    targetBrand: item.brand,
                    targetDomain: brandDomain,
                    method: `Typosquatting (Edit distance: ${dist})`,
                    distance: dist
                };
            }
        }
    }

    return { isLookalike: false };
}

/**
 * Audit live DNS records for a given domain
 *
 * @param {string} domain
 * @returns {Promise<object>}
 */
async function auditDomain(domain) {
    const cleanDomain = String(domain || "").trim().toLowerCase().replace(/^@/, "");

    if (!cleanDomain || !cleanDomain.includes(".")) {
        return {
            domain: cleanDomain,
            valid: false,
            message: "Invalid domain format."
        };
    }

    const tld = cleanDomain.split(".").pop();
    const isHighRiskTld = HIGH_RISK_TLDS.has(tld);
    const lookalike = detectTyposquatting(cleanDomain);

    const findings = [];
    let domainRiskScore = 0;

    if (isHighRiskTld) {
        domainRiskScore += 25;
        findings.push(`Domain uses high-abuse/phishing top-level domain: .${tld}`);
    }

    if (lookalike.isLookalike) {
        domainRiskScore += 45;
        findings.push(`Deceptive typosquatting/lookalike targeting brand '${lookalike.targetBrand}' detected via ${lookalike.method}.`);
    }

    // Query live DNS records asynchronously in parallel with safe error fallbacks
    const [mxResults, aResults, txtResults, nsResults] = await Promise.all([
        dns.resolveMx(cleanDomain).catch(() => []),
        dns.resolve4(cleanDomain).catch(() => []),
        dns.resolveTxt(cleanDomain).catch(() => []),
        dns.resolveNs(cleanDomain).catch(() => [])
    ]);

    const formattedTxt = txtResults.map(parts => parts.join(""));
    const hasMx = Array.isArray(mxResults) && mxResults.length > 0;
    const hasA = Array.isArray(aResults) && aResults.length > 0;
    const hasNs = Array.isArray(nsResults) && nsResults.length > 0;

    if (!hasMx) {
        // Missing MX records for an email sender domain is a primary indicator of unauthorized sender
        domainRiskScore += 30;
        findings.push("No valid MX (Mail Exchange) records found in DNS for this domain.");
    }

    if (!hasA && !hasMx) {
        domainRiskScore += 20;
        findings.push("Domain does not resolve to any active A or MX records in public DNS.");
    }

    domainRiskScore = Math.min(domainRiskScore, 100);

    return {
        domain: cleanDomain,
        tld: tld,
        isHighRiskTld: isHighRiskTld,
        lookalike: lookalike,
        hasMx: hasMx,
        mxRecords: mxResults,
        hasA: hasA,
        aRecords: aResults,
        hasNs: hasNs,
        nsRecords: nsResults,
        txtRecordsCount: formattedTxt.length,
        domainRiskScore: domainRiskScore,
        findings: findings
    };
}

module.exports = {
    auditDomain,
    detectTyposquatting
};
