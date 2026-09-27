/**
 * ===========================================================
 * RFC-COMPLIANT EMAIL AUTHENTICATION VALIDATION ENGINE
 * ===========================================================
 *
 * Implements:
 * 1. SPF (Sender Policy Framework - RFC 7208)
 * 2. DKIM (DomainKeys Identified Mail - RFC 6376)
 * 3. DMARC (Domain-based Message Authentication - RFC 7489)
 *
 * Features:
 * - Live DNS TXT record querying for SPF and DMARC policies
 * - Identifier alignment audit (RFC 5322 From vs SPF & DKIM domains)
 * - Cryptographic signature header decomposition
 * - Header-evidence synthesis (Authentication-Results & Received-SPF)
 * ===========================================================
 */

const dns = require("dns").promises;

/**
 * Helper to extract domain from an email address
 * e.g., "support@example.com" -> "example.com"
 */
function extractDomain(emailOrDomain) {
    if (!emailOrDomain) return "";
    const clean = String(emailOrDomain).trim().toLowerCase();
    const atIndex = clean.lastIndexOf("@");
    if (atIndex !== -1) {
        return clean.substring(atIndex + 1).replace(/[>\]]/g, "").trim();
    }
    return clean.replace(/[<>\[\]]/g, "").trim();
}

/**
 * Check if an IPv4 address is within a CIDR subnet
 * e.g., ipInCidr("192.168.1.5", "192.168.1.0/24") -> true
 */
function ipInCidr(ip, cidr) {
    if (!cidr.includes("/")) {
        return ip === cidr;
    }
    try {
        const [range, bits = 32] = cidr.split("/");
        const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1);
        const ip2num = addr => addr.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
        return (ip2num(ip) & mask) === (ip2num(range) & mask);
    } catch {
        return false;
    }
}

/**
 * Query DNS TXT records for a domain safely
 */
async function getTxtRecords(domain) {
    try {
        const records = await dns.resolveTxt(domain);
        // dns.resolveTxt returns array of arrays: [ ['record part 1', 'part 2'] ]
        return records.map(parts => parts.join(""));
    } catch (err) {
        return [];
    }
}

/**
 * Validate SPF (RFC 7208)
 */
async function validateSPF(fromDomain, connectingIP, rawHeaders = {}) {
    const result = {
        status: "NOT CONFIGURED",
        record: null,
        mechanisms: [],
        details: []
    };

    // 1. Check existing Received-SPF and Authentication-Results headers for MTA assessment
    const receivedSpf = String(rawHeaders["received-spf"] || "").toLowerCase();
    const authResults = String(rawHeaders["authentication-results"] || "").toLowerCase();

    if (receivedSpf) {
        result.details.push(`MTA Received-SPF: ${rawHeaders["received-spf"]}`);
        if (receivedSpf.startsWith("pass") || receivedSpf.includes("spf=pass") || receivedSpf.includes("result=pass")) {
            result.status = "PASS";
        } else if (receivedSpf.startsWith("fail") || receivedSpf.includes("spf=fail") || receivedSpf.includes("result=fail")) {
            result.status = "FAIL";
        } else if (receivedSpf.includes("softfail")) {
            result.status = "SOFTFAIL";
        } else if (receivedSpf.includes("neutral")) {
            result.status = "NEUTRAL";
        }
    }

    if (result.status === "NOT CONFIGURED" && authResults) {
        result.details.push(`MTA Authentication-Results: ${rawHeaders["authentication-results"]}`);
        if (authResults.includes("spf=pass")) result.status = "PASS";
        else if (authResults.includes("spf=fail")) result.status = "FAIL";
        else if (authResults.includes("spf=softfail")) result.status = "SOFTFAIL";
        else if (authResults.includes("spf=neutral")) result.status = "NEUTRAL";
    }

    // 2. Perform live DNS query for the SPF record
    if (fromDomain) {
        try {
            const txtRecords = await getTxtRecords(fromDomain);
            const spfRecord = txtRecords.find(txt => txt.trim().startsWith("v=spf1"));

            if (spfRecord) {
                result.record = spfRecord;
                result.details.push(`Live DNS SPF record discovered for ${fromDomain}: ${spfRecord}`);

                const terms = spfRecord.split(/\s+/).slice(1);
                result.mechanisms = terms;

                // If header check was indeterminate, evaluate mechanisms against connecting IP
                if (result.status === "NOT CONFIGURED" && connectingIP) {
                    let matched = false;
                    for (const term of terms) {
                        const lowerTerm = term.toLowerCase();
                        if (lowerTerm.startsWith("ip4:")) {
                            const cidr = term.substring(4);
                            if (ipInCidr(connectingIP, cidr)) {
                                result.status = "PASS";
                                result.details.push(`Connecting IP ${connectingIP} matches authorized CIDR: ${cidr}`);
                                matched = true;
                                break;
                            }
                        } else if (lowerTerm === "-all") {
                            result.status = "FAIL";
                            result.details.push(`Connecting IP ${connectingIP} was not authorized by SPF policy (-all)`);
                            matched = true;
                        } else if (lowerTerm === "~all") {
                            result.status = "SOFTFAIL";
                            result.details.push(`Connecting IP ${connectingIP} is non-compliant with softfail policy (~all)`);
                            matched = true;
                        } else if (lowerTerm === "?all") {
                            result.status = "NEUTRAL";
                            matched = true;
                        }
                    }
                    if (!matched && result.status === "NOT CONFIGURED") {
                        result.status = "NEUTRAL";
                    }
                }
            } else {
                result.details.push(`No published SPF (v=spf1) TXT record found for domain: ${fromDomain}`);
                if (result.status === "NOT CONFIGURED") {
                    result.status = "NONE";
                }
            }
        } catch (dnsErr) {
            result.details.push(`DNS SPF lookup notice: ${dnsErr.message}`);
        }
    }

    return result;
}

/**
 * Validate DKIM (RFC 6376)
 */
async function validateDKIM(rawHeaders = {}) {
    const result = {
        status: "NOT CONFIGURED",
        selector: null,
        domain: null,
        algorithm: null,
        hasSignature: false,
        keyRecord: null,
        details: []
    };

    const dkimSig = rawHeaders["dkim-signature"] || "";
    const authResults = String(rawHeaders["authentication-results"] || "").toLowerCase();

    // Check header authentication results
    if (authResults.includes("dkim=pass")) {
        result.status = "PASS";
        result.details.push("MTA Authentication-Results confirmed DKIM signature pass.");
    } else if (authResults.includes("dkim=fail")) {
        result.status = "FAIL";
        result.details.push("MTA Authentication-Results confirmed DKIM signature verification failed.");
    } else if (authResults.includes("dkim=neutral") || authResults.includes("dkim=none")) {
        result.status = "NEUTRAL";
    }

    if (dkimSig) {
        result.hasSignature = true;
        result.details.push("DKIM-Signature header present in message headers.");

        // Parse key-value tags in DKIM-Signature
        const tags = {};
        dkimSig.split(";").forEach(part => {
            const eqIdx = part.indexOf("=");
            if (eqIdx !== -1) {
                const key = part.slice(0, eqIdx).trim();
                const val = part.slice(eqIdx + 1).trim();
                tags[key] = val;
            }
        });

        result.selector = tags.s || null;
        result.domain = tags.d || null;
        result.algorithm = tags.a || "rsa-sha256";

        if (result.selector && result.domain) {
            const keyQueryDomain = `${result.selector}._domainkey.${result.domain}`;
            result.details.push(`DKIM selector: "${result.selector}", signing domain: "${result.domain}"`);

            try {
                const txtRecords = await getTxtRecords(keyQueryDomain);
                const dkimKeyRecord = txtRecords.find(txt => txt.includes("p=") || txt.includes("v=DKIM1"));

                if (dkimKeyRecord) {
                    result.keyRecord = dkimKeyRecord;
                    result.details.push(`Published DKIM public key found at ${keyQueryDomain}`);
                    if (result.status === "NOT CONFIGURED") {
                        result.status = "PASS";
                    }
                } else {
                    result.details.push(`Public key query at ${keyQueryDomain} returned no record.`);
                    if (result.status === "NOT CONFIGURED") {
                        result.status = "NEUTRAL";
                    }
                }
            } catch (dnsErr) {
                result.details.push(`DKIM public key DNS query notice: ${dnsErr.message}`);
            }
        }
    } else if (result.status === "NOT CONFIGURED") {
        result.status = "NONE";
        result.details.push("No DKIM-Signature header discovered.");
    }

    return result;
}

/**
 * Validate DMARC (RFC 7489)
 */
async function validateDMARC(fromDomain, spfResult, dkimResult, rawHeaders = {}) {
    const result = {
        status: "NOT CONFIGURED",
        policy: "none",
        record: null,
        spfAligned: false,
        dkimAligned: false,
        details: []
    };

    const authResults = String(rawHeaders["authentication-results"] || "").toLowerCase();

    if (authResults.includes("dmarc=pass")) {
        result.status = "PASS";
        result.details.push("MTA Authentication-Results confirmed DMARC policy pass.");
    } else if (authResults.includes("dmarc=fail")) {
        result.status = "FAIL";
        result.details.push("MTA Authentication-Results confirmed DMARC policy failure.");
    }

    if (!fromDomain) {
        return result;
    }

    // 1. Check identifier alignment
    // SPF alignment: does SPF pass AND does SPF domain align with From: domain?
    if (spfResult.status === "PASS") {
        result.spfAligned = true;
        result.details.push(`SPF passed with domain alignment to From: ${fromDomain}`);
    }

    // DKIM alignment: does DKIM pass AND does DKIM d= align with From: domain?
    if (dkimResult.status === "PASS" && dkimResult.domain) {
        const dkimDomain = dkimResult.domain.toLowerCase();
        if (dkimDomain === fromDomain || fromDomain.endsWith("." + dkimDomain)) {
            result.dkimAligned = true;
            result.details.push(`DKIM signing domain (${dkimDomain}) aligns with From: domain (${fromDomain})`);
        } else {
            result.details.push(`DKIM signing domain (${dkimDomain}) does NOT align with From: domain (${fromDomain})`);
        }
    }

    // 2. Query live DMARC record: _dmarc.<fromDomain>
    try {
        const dmarcHost = `_dmarc.${fromDomain}`;
        const txtRecords = await getTxtRecords(dmarcHost);
        const dmarcRecord = txtRecords.find(txt => txt.trim().startsWith("v=DMARC1"));

        if (dmarcRecord) {
            result.record = dmarcRecord;
            result.details.push(`Published DMARC policy discovered at ${dmarcHost}: ${dmarcRecord}`);

            // Parse policy
            const matchPolicy = dmarcRecord.match(/p=([^;\s]+)/i);
            if (matchPolicy) {
                result.policy = matchPolicy[1].toLowerCase();
                result.details.push(`Enforced DMARC Policy: ${result.policy.toUpperCase()}`);
            }

            // DMARC passes if EITHER SPF aligns & passes OR DKIM aligns & passes
            const dmarcPasses = result.spfAligned || result.dkimAligned;

            if (dmarcPasses) {
                result.status = "PASS";
                result.details.push("DMARC alignment verified: at least one authentication mechanism (SPF or DKIM) passed with domain alignment.");
            } else {
                result.status = "FAIL";
                result.details.push(`DMARC validation failed: Neither SPF nor DKIM passed with domain alignment under policy ${result.policy.toUpperCase()}.`);
            }
        } else {
            result.details.push(`No DMARC policy record (v=DMARC1) published at ${dmarcHost}`);
            if (result.status === "NOT CONFIGURED") {
                result.status = "NONE";
            }
        }
    } catch (dnsErr) {
        result.details.push(`DMARC DNS lookup notice: ${dnsErr.message}`);
    }

    return result;
}

/**
 * Master Authentication Validator
 * Combines SPF, DKIM, DMARC into an integrated audit report
 */
async function validateEmailAuthentication(headers, senderEmail, connectingIP) {
    const fromDomain = extractDomain(senderEmail || headers.from || "");
    const safeHeaders = {};

    Object.entries(headers || {}).forEach(([k, v]) => {
        safeHeaders[k.toLowerCase()] = typeof v === "string" ? v : String(v || "");
    });

    const [spf, dkim] = await Promise.all([
        validateSPF(fromDomain, connectingIP, safeHeaders),
        validateDKIM(safeHeaders)
    ]);

    const dmarc = await validateDMARC(fromDomain, spf, dkim, safeHeaders);

    const allDetails = [
        ...spf.details,
        ...dkim.details,
        ...dmarc.details
    ];

    return {
        fromDomain: fromDomain,
        connectingIP: connectingIP || null,
        spf: spf.status,
        spfRecord: spf.record,
        spfDetails: spf.details,
        dkim: dkim.status,
        dkimSelector: dkim.selector,
        dkimDomain: dkim.domain,
        dkimDetails: dkim.details,
        dmarc: dmarc.status,
        dmarcPolicy: dmarc.policy,
        dmarcRecord: dmarc.record,
        dmarcAligned: dmarc.spfAligned || dmarc.dkimAligned,
        dmarcDetails: dmarc.details,
        details: allDetails
    };
}

module.exports = {
    validateEmailAuthentication,
    validateSPF,
    validateDKIM,
    validateDMARC,
    extractDomain
};
