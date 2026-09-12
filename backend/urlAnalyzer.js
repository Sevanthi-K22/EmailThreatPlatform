// ======================================================
// URL + DOMAIN INTELLIGENCE ENGINE
// ======================================================

// Suspicious top-level domains commonly seen in
// phishing, scam, and disposable domains.
const suspiciousTLDs = [
    "xyz",
    "top",
    "click",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "pw",
    "zip",
    "review",
    "country",
    "work",
    "party",
    "date",
    "win"
];


// Common URL-shortening services.
const shortenerDomains = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly"
];


// Brands we want to check for impersonation.
// This list can be expanded later.
const protectedBrands = [
    "microsoft",
    "google",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "docusign",
    "adobe",
    "dropbox",
    "whatsapp",
    "instagram",
    "bank",
    "office365",
    "outlook"
];


// ======================================================
// HELPER: GET DOMAIN
// ======================================================

function getDomain(url) {

    try {

        let normalizedURL =
            url.trim();

        // Some extracted URLs may contain
        // punctuation at the end.
        normalizedURL =
            normalizedURL.replace(
                /[),.;!?]+$/,
                ""
            );

        const parsed =
            new URL(normalizedURL);

        return parsed.hostname
            .toLowerCase();

    }

    catch (error) {

        return "";

    }

}


// ======================================================
// HELPER: GET TLD
// ======================================================

function getTLD(domain) {

    const parts =
        domain.split(".");

    if (parts.length < 2) {

        return "";

    }

    return parts[
        parts.length - 1
    ].toLowerCase();

}


// ======================================================
// HELPER: CHECK IP ADDRESS
// ======================================================

function isIPAddress(domain) {

    const ipv4Regex =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    return ipv4Regex.test(domain);

}


// ======================================================
// HELPER: CHECK URL SHORTENER
// ======================================================

function isShortener(domain) {

    return shortenerDomains.includes(
        domain
    );

}


// ======================================================
// HELPER: SIMILARITY
// ======================================================

// Simple Levenshtein distance.
// Used to detect small spelling changes such as:
//
// microsoft
// micros0ft
//
// This is intentionally kept simple for the MVP.

function levenshteinDistance(
    a,
    b
) {

    const matrix = [];


    for (
        let i = 0;
        i <= b.length;
        i++
    ) {

        matrix[i] = [i];

    }


    for (
        let j = 0;
        j <= a.length;
        j++
    ) {

        matrix[0][j] = j;

    }


    for (
        let i = 1;
        i <= b.length;
        i++
    ) {

        for (
            let j = 1;
            j <= a.length;
            j++
        ) {

            if (
                b.charAt(i - 1) ===
                a.charAt(j - 1)
            ) {

                matrix[i][j] =
                    matrix[i - 1][j - 1];

            }

            else {

                matrix[i][j] =
                    Math.min(

                        matrix[i - 1][j] + 1,

                        matrix[i][j - 1] + 1,

                        matrix[i - 1][j - 1] + 1

                    );

            }

        }

    }


    return matrix[b.length][a.length];

}


// ======================================================
// HELPER: NORMALIZE LOOKALIKE TEXT
// ======================================================

// Converts common character substitutions.
//
// micros0ft → microsoft
// paypa1 → paypal
// g00gle → google

function normalizeLookalike(
    text
) {

    return text
        .toLowerCase()
        .replace(/0/g, "o")
        .replace(/1/g, "l")
        .replace(/3/g, "e")
        .replace(/4/g, "a")
        .replace(/5/g, "s")
        .replace(/7/g, "t");
}


// ======================================================
// BRAND IMPERSONATION DETECTION
// ======================================================

function detectBrandImpersonation(
    domain
) {

    const result = {

        detected: false,

        brand: null,

        reason: null

    };


    const domainWithoutTLD =
        domain
            .split(".")
            .slice(
                0,
                -1
            )
            .join(".");


    const normalizedDomain =
        normalizeLookalike(
            domainWithoutTLD
        );


    for (
        const brand of protectedBrands
    ) {

        // Exact appearance.
        if (
            domainWithoutTLD
                .includes(brand)
        ) {

            result.detected =
                true;

            result.brand =
                brand;

            result.reason =
                `Domain contains the protected brand name "${brand}".`;

            return result;

        }


        // Lookalike appearance.
        if (
            normalizedDomain
                .includes(brand)
        ) {

            result.detected =
                true;

            result.brand =
                brand;

            result.reason =
                `Domain appears to imitate the "${brand}" brand using lookalike characters.`;

            return result;

        }


        // Compare individual domain parts.
        const domainParts =
            domainWithoutTLD
                .split(/[-_.]/);


        for (
            const part of domainParts
        ) {

            if (
                part.length < 4
            ) {

                continue;

            }


            const distance =
                levenshteinDistance(
                    part,
                    brand
                );


            if (
                distance <= 2
            ) {

                result.detected =
                    true;

                result.brand =
                    brand;

                result.reason =
                    `Domain name "${part}" is very similar to the legitimate "${brand}" name.`;

                return result;

            }

        }

    }


    return result;

}


// ======================================================
// URL ANALYSIS
// ======================================================

function analyzeURL(
    url
) {

    const findings = [];

    let score = 0;


    // ==================================================
    // BASIC URL INFORMATION
    // ==================================================

    let parsedURL;


    try {

        parsedURL =
            new URL(
                url.trim()
            );

    }

    catch (error) {

        return {

            url: url,

            domain: "",

            protocol: "",

            riskScore: 100,

            verdict: "HIGH RISK",

            findings: [

                {

                    type:
                        "INVALID_URL",

                    severity:
                        "HIGH",

                    score:
                        100,

                    description:
                        "The extracted URL could not be parsed safely."

                }

            ]

        };

    }


    const domain =
        parsedURL.hostname
            .toLowerCase();


    const protocol =
        parsedURL.protocol
            .replace(
                ":",
                ""
            );


    const tld =
        getTLD(
            domain
        );


    // ==================================================
    // HTTPS CHECK
    // ==================================================

    if (
        protocol !== "https"
    ) {

        score += 15;


        findings.push({

            type:
                "NO_HTTPS",

            severity:
                "MEDIUM",

            score:
                15,

            description:
                "The URL does not use HTTPS."

        });

    }


    // ==================================================
    // IP ADDRESS URL
    // ==================================================

    if (
        isIPAddress(domain)
    ) {

        score += 30;


        findings.push({

            type:
                "IP_BASED_URL",

            severity:
                "HIGH",

            score:
                30,

            description:
                "The URL uses a raw IP address instead of a normal domain name."

        });

    }


    // ==================================================
    // SUSPICIOUS TLD
    // ==================================================

    if (
        suspiciousTLDs.includes(tld)
    ) {

        score += 25;


        findings.push({

            type:
                "SUSPICIOUS_TLD",

            severity:
                "MEDIUM",

            score:
                25,

            description:
                `The domain uses the suspicious ".${tld}" top-level domain.`

        });

    }


    // ==================================================
    // URL SHORTENER
    // ==================================================

    if (
        isShortener(domain)
    ) {

        score += 20;


        findings.push({

            type:
                "URL_SHORTENER",

            severity:
                "MEDIUM",

            score:
                20,

            description:
                "The URL uses a URL-shortening service, which can hide the final destination."

        });

    }


    // ==================================================
    // BRAND IMPERSONATION
    // ==================================================

    const brandResult =
        detectBrandImpersonation(
            domain
        );


    if (
        brandResult.detected
    ) {

        score += 35;


        findings.push({

            type:
                "BRAND_IMPERSONATION",

            severity:
                "HIGH",

            score:
                35,

            description:
                brandResult.reason

        });

    }


    // ==================================================
    // EXCESSIVE SUBDOMAINS
    // ==================================================

    const domainParts =
        domain.split(".");


    if (
        domainParts.length >= 4
    ) {

        score += 15;


        findings.push({

            type:
                "EXCESSIVE_SUBDOMAINS",

            severity:
                "MEDIUM",

            score:
                15,

            description:
                "The domain contains an unusually large number of subdomain levels."

        });

    }


    // ==================================================
    // LONG URL
    // ==================================================

    if (
        url.length > 150
    ) {

        score += 10;


        findings.push({

            type:
                "LONG_URL",

            severity:
                "LOW",

            score:
                10,

            description:
                "The URL is unusually long and may be attempting to hide suspicious parameters."

        });

    }


    // ==================================================
    // SUSPICIOUS URL KEYWORDS
    // ==================================================

    const suspiciousKeywords = [

        "login",

        "verify",

        "verification",

        "secure",

        "security",

        "account",

        "password",

        "update",

        "confirm",

        "signin",

        "authenticate",

        "wallet",

        "payment",

        "invoice",

        "banking"

    ];


    const lowerURL =
        url.toLowerCase();


    const matchedKeywords =
        suspiciousKeywords.filter(
            keyword =>
                lowerURL.includes(
                    keyword
                )
        );


    if (
        matchedKeywords.length > 0
    ) {

        score += 10;


        findings.push({

            type:
                "SUSPICIOUS_KEYWORD",

            severity:
                "LOW",

            score:
                10,

            description:
                `URL contains security-sensitive keywords: ${matchedKeywords.join(", ")}.`

        });

    }


    // ==================================================
    // CAP SCORE
    // ==================================================

    score =
        Math.min(
            score,
            100
        );


    // ==================================================
    // VERDICT
    // ==================================================

    let verdict;


    if (
        score >= 70
    ) {

        verdict =
            "HIGH RISK";

    }

    else if (
        score >= 40
    ) {

        verdict =
            "MEDIUM RISK";

    }

    else {

        verdict =
            "LOW RISK";

    }


    // ==================================================
    // RETURN RESULT
    // ==================================================

    return {

        url:
            url,

        domain:
            domain,

        protocol:
            protocol,

        tld:
            tld,

        riskScore:
            score,

        verdict:
            verdict,

        brand:
            brandResult.brand,

        findings:
            findings

    };

}


// ======================================================
// ANALYZE MULTIPLE URLs
// ======================================================

function analyzeURLs(
    urls
) {

    if (
        !Array.isArray(urls)
    ) {

        return [];

    }


    return urls.map(
        url =>
            analyzeURL(
                url
            )
    );

}


// ======================================================
// EXPORT
// ======================================================

module.exports = {

    analyzeURL,

    analyzeURLs

};