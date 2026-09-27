const { simpleParser } = require("mailparser");
const crypto = require("crypto");


// ======================================================
// HELPER: PARSE AUTHENTICATION HEADERS (SPF, DKIM, DMARC)
// ======================================================

function parseAuthenticationHeaders(headers) {
    const auth = {
        spf: "NOT CONFIGURED",
        dkim: "NOT CONFIGURED",
        dmarc: "NOT CONFIGURED",
        details: []
    };

    const authResults =
        headers["authentication-results"] ||
        headers["arc-authentication-results"] ||
        "";

    const receivedSpf =
        headers["received-spf"] ||
        "";

    const dkimSignature =
        headers["dkim-signature"] ||
        "";

    if (receivedSpf) {
        auth.details.push(`Received-SPF: ${receivedSpf}`);
        const lowerSpf = receivedSpf.toLowerCase();
        if (lowerSpf.startsWith("pass") || lowerSpf.includes("spf=pass") || lowerSpf.includes("result=pass")) {
            auth.spf = "PASS";
        } else if (lowerSpf.startsWith("fail") || lowerSpf.includes("spf=fail") || lowerSpf.includes("result=fail")) {
            auth.spf = "FAIL";
        } else if (lowerSpf.includes("softfail")) {
            auth.spf = "SOFTFAIL";
        } else if (lowerSpf.includes("neutral")) {
            auth.spf = "NEUTRAL";
        }
    }

    if (authResults) {
        auth.details.push(`Authentication-Results: ${authResults}`);
        const lowerAuth = authResults.toLowerCase();

        if (auth.spf === "NOT CONFIGURED") {
            if (lowerAuth.includes("spf=pass")) auth.spf = "PASS";
            else if (lowerAuth.includes("spf=fail")) auth.spf = "FAIL";
            else if (lowerAuth.includes("spf=softfail")) auth.spf = "SOFTFAIL";
            else if (lowerAuth.includes("spf=neutral")) auth.spf = "NEUTRAL";
        }

        if (lowerAuth.includes("dkim=pass")) auth.dkim = "PASS";
        else if (lowerAuth.includes("dkim=fail")) auth.dkim = "FAIL";
        else if (lowerAuth.includes("dkim=neutral") || lowerAuth.includes("dkim=none")) auth.dkim = "NEUTRAL";

        if (lowerAuth.includes("dmarc=pass")) auth.dmarc = "PASS";
        else if (lowerAuth.includes("dmarc=fail")) auth.dmarc = "FAIL";
        else if (lowerAuth.includes("dmarc=none")) auth.dmarc = "NONE";
    }

    if (dkimSignature && auth.dkim === "NOT CONFIGURED") {
        auth.dkim = "PRESENT";
        auth.details.push("DKIM-Signature header present.");
    }

    return auth;
}


// ======================================================
// HELPER: DETECT LINK SPOOFING (DISPLAY TEXT VS HREF)
// ======================================================

function extractLinkMismatches(html) {
    if (!html || typeof html !== "string") {
        return [];
    }

    const mismatches = [];
    const linkRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
    let match;

    while ((match = linkRegex.exec(html)) !== null) {
        const href = match[1].trim();
        const text = match[2].replace(/<[^>]*>/g, "").trim();

        if (/^https?:\/\//i.test(text)) {
            try {
                const hrefUrl = new URL(href);
                const textUrl = new URL(text);

                if (hrefUrl.hostname.toLowerCase() !== textUrl.hostname.toLowerCase()) {
                    mismatches.push({
                        displayText: text,
                        actualUrl: href,
                        displayedDomain: textUrl.hostname.toLowerCase(),
                        actualDomain: hrefUrl.hostname.toLowerCase()
                    });
                }
            } catch (e) {
                // Ignore parse errors on malformed links
            }
        }
    }

    return mismatches;
}


// ======================================================
// HELPER: PARSE STRUCTURED MTA RELAY TRACE
// ======================================================

function parseRelayTrace(safeReceived) {
    if (!Array.isArray(safeReceived) || safeReceived.length === 0) {
        return [];
    }

    // Reverse to establish chronological transit order:
    // Hop 1 = Earliest origin MTA / Client submission
    // Hop N = Final destination MX receiver
    const reversed = [...safeReceived].reverse();
    const hops = [];

    for (let i = 0; i < reversed.length; i++) {
        const headerStr = reversed[i];
        const hopNumber = i + 1;

        // Extract 'from' host
        const fromMatch = headerStr.match(/from\s+([^\s;()]+(?:\s*\([^)]*\))?)/i);
        const fromHost = fromMatch ? fromMatch[1].trim() : "Unknown";

        // Extract 'by' host
        const byMatch = headerStr.match(/by\s+([^\s;]+)/i);
        const byHost = byMatch ? byMatch[1].trim() : "Unknown";

        // Extract IP address from bracket or raw notation
        const ipMatch = headerStr.match(/\[((?:\d{1,3}\.){3}\d{1,3})\]/) ||
                        headerStr.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        const ip = ipMatch ? (ipMatch[1] || ipMatch[0]) : null;

        // Extract protocol
        const protoMatch = headerStr.match(/with\s+([A-Za-z0-9_-]+)/i);
        const protocol = protoMatch ? protoMatch[1].toUpperCase() : "SMTP";

        // Extract timestamp after semicolon
        let timestamp = null;
        let delaySeconds = 0;
        const semiIndex = headerStr.lastIndexOf(";");
        if (semiIndex !== -1) {
            const rawDate = headerStr.substring(semiIndex + 1).trim();
            const parsedDate = new Date(rawDate);
            if (!isNaN(parsedDate.getTime())) {
                timestamp = parsedDate.toISOString();
                if (hops.length > 0 && hops[hops.length - 1].timestamp) {
                    const prevDate = new Date(hops[hops.length - 1].timestamp);
                    const diff = Math.round((parsedDate.getTime() - prevDate.getTime()) / 1000);
                    delaySeconds = Math.max(0, diff);
                }
            }
        }

        let hopType = "Transit Relay MTA";
        if (hopNumber === 1) {
            hopType = "Origin MTA / Submitting Client";
        } else if (hopNumber === reversed.length) {
            hopType = "Destination Inbound Gateway";
        }

        hops.push({
            hop: hopNumber,
            type: hopType,
            from: fromHost,
            by: byHost,
            ip: ip,
            protocol: protocol,
            timestamp: timestamp,
            delaySeconds: delaySeconds,
            raw: headerStr
        });
    }

    return hops;
}


// ======================================================
// EMAIL PARSER
// ======================================================

async function parseEmail(fileBuffer) {

    // ==================================================
    // FORENSIC CRYPTOGRAPHIC HASHES
    // ==================================================

    const sha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    const md5 = crypto.createHash("md5").update(fileBuffer).digest("hex");
    const sha1 = crypto.createHash("sha1").update(fileBuffer).digest("hex");
    const hashes = {
        sha256: sha256,
        md5: md5,
        sha1: sha1,
        sizeBytes: fileBuffer.length
    };

    // ==================================================
    // PARSE EMAIL
    // ==================================================

    const parsed =
        await simpleParser(fileBuffer);


    // ==================================================
    // EXTRACT ALL HEADERS
    // ==================================================

    const headers = {};

    for (const [key, value] of parsed.headers) {
        try {
            if (value === null || value === undefined) {
                headers[key] = "";
            } else if (typeof value === "string") {
                headers[key] = value;
            } else if (value instanceof Date) {
                headers[key] = value.toISOString();
            } else if (typeof value === "object") {
                if (value.text) {
                    headers[key] = value.text;
                } else if (value.value) {
                    headers[key] = typeof value.value === "string"
                        ? value.value
                        : (Array.isArray(value.value)
                            ? value.value.map(v => v.address || v.name || JSON.stringify(v)).join(", ")
                            : JSON.stringify(value.value));
                } else {
                    headers[key] = JSON.stringify(value);
                }
            } else {
                headers[key] = String(value);
            }
        } catch (error) {
            headers[key] = String(value);
        }
    }


    // ==================================================
    // EMAIL BODY & HTML
    // ==================================================

    const body =
        parsed.text || "";

    const htmlBody =
        parsed.html || "";


    // ==================================================
    // EXTRACT URLs (FROM BODY & HTML)
    // ==================================================

    const urlRegex =
        /(https?:\/\/[^\s<>"']+)/gi;

    const urls =
        (body + " " + htmlBody).match(urlRegex) || [];

    const uniqueURLs =
        [...new Set(urls)];


    // ==================================================
    // EXTRACT IP ADDRESSES FROM BODY
    // ==================================================

    const ipRegex =
        /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;


    const bodyIPs =
        body.match(ipRegex) || [];


    const uniqueIPs =
        [...new Set(bodyIPs)];


    // ==================================================
    // EXTRACT RECEIVED HEADERS
    // ==================================================

    const receivedHeader =
        parsed.headers.get("received");


    let received = [];


    if (receivedHeader) {

        if (Array.isArray(receivedHeader)) {

            received =
                receivedHeader;

        }

        else {

            received =
                [receivedHeader];

        }

    }


    // ==================================================
    // CONVERT RECEIVED HEADERS TO STRINGS
    // ==================================================

    const safeReceived = [];


    received.forEach(
        header => {

            try {

                if (
                    header === null ||
                    header === undefined
                ) {

                    return;

                }


                if (
                    typeof header === "string"
                ) {

                    safeReceived.push(
                        header
                    );

                }

                else if (
                    header instanceof Date
                ) {

                    safeReceived.push(
                        header.toISOString()
                    );

                }

                else {

                    safeReceived.push(
                        String(header)
                    );

                }

            }

            catch (error) {

                console.error(
                    "Received header conversion error:",
                    error
                );

            }

        }
    );


    // ==================================================
    // EXTRACT IPs FROM RECEIVED HEADERS
    // ==================================================

    const headerIPs = [];


    safeReceived.forEach(
        header => {

            const matches =
                String(header)
                    .match(ipRegex) || [];


            matches.forEach(
                ip => {

                    if (
                        !headerIPs.includes(ip)
                    ) {

                        headerIPs.push(ip);

                    }

                }
            );

        }
    );


    // ==================================================
    // EXTRACT REPLY-TO
    // ==================================================

    let replyTo = "";


    if (parsed.replyTo) {

        try {

            if (
                typeof parsed.replyTo === "string"
            ) {

                replyTo =
                    parsed.replyTo;

            }

            else if (
                parsed.replyTo.text
            ) {

                replyTo =
                    parsed.replyTo.text;

            }

            else {

                replyTo =
                    String(
                        parsed.replyTo
                    );

            }

        }

        catch (error) {

            replyTo =
                String(
                    parsed.replyTo
                );

        }

    }


    // ==================================================
    // EXTRACT SENDER
    // ==================================================

    let sender =
        "Unknown";


    try {

        if (parsed.from) {

            if (parsed.from.text) {

                sender =
                    parsed.from.text;

            }

            else {

                sender =
                    String(
                        parsed.from
                    );

            }

        }

    }

    catch (error) {

        sender =
            "Unknown";

    }


    // ==================================================
    // EXTRACT RECIPIENT
    // ==================================================

    let recipient =
        "Unknown";


    try {

        if (parsed.to) {

            if (parsed.to.text) {

                recipient =
                    parsed.to.text;

            }

            else {

                recipient =
                    String(
                        parsed.to
                    );

            }

        }

    }

    catch (error) {

        recipient =
            "Unknown";

    }


    // ==================================================
    // EXTRACT SUBJECT
    // ==================================================

    const subject =
        parsed.subject
            ? String(parsed.subject)
            : "No Subject";


    // ==================================================
    // EXTRACT DATE
    // ==================================================

    let emailDate = null;


    try {

        if (parsed.date) {

            if (
                parsed.date instanceof Date
            ) {

                emailDate =
                    parsed.date.toISOString();

            }

            else {

                emailDate =
                    String(parsed.date);

            }

        }

    }

    catch (error) {

        emailDate = null;

    }


    // ==================================================
    // EXTRACT MESSAGE ID
    // ==================================================

    const messageId =
        parsed.messageId
            ? String(parsed.messageId)
            : null;


    // ==================================================
    // EXTRACT ATTACHMENTS
    // ==================================================

    const attachments = (parsed.attachments || []).map(att => ({
        filename: att.filename || "unnamed_attachment",
        contentType: att.contentType || "application/octet-stream",
        size: att.size || (att.content ? att.content.length : 0),
        checksum: att.checksum || ""
    }));


    // ==================================================
    // EXTRACT AUTHENTICATION STATUS (SPF, DKIM, DMARC)
    // ==================================================

    const authentication = parseAuthenticationHeaders(headers);


    // ==================================================
    // EXTRACT LINK MISMATCHES (LINK SPOOFING)
    // ==================================================

    const linkMismatches = extractLinkMismatches(htmlBody);


    // ==================================================
    // RETURN COMPLETE EMAIL OBJECT
    // ==================================================

    return {

        sender:
            sender,

        recipient:
            recipient,

        subject:
            subject,

        date:
            emailDate,

        messageId:
            messageId,

        replyTo:
            replyTo,

        body:
            body,

        htmlBody:
            htmlBody,

        headers:
            headers,

        urls:
            uniqueURLs,

        ips:
            uniqueIPs,

        received:
            safeReceived,

        headerIPs:
            headerIPs,

        attachments:
            attachments,

        authentication:
            authentication,

        linkMismatches:
            linkMismatches,

        hashes:
            hashes,

        relayTrace:
            parseRelayTrace(safeReceived)

    };

}


// ======================================================
// EXPORT
// ======================================================

module.exports = {

    parseEmail

};