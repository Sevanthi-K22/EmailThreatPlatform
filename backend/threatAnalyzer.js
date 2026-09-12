const { analyzeURLs } = require("./urlAnalyzer");


// ======================================================
// THREAT ANALYSIS ENGINE
// ======================================================

function analyzeThreat(email) {

    let score = 0;

    const findings = [];


    // ==================================================
    // HELPER FUNCTION
    // ==================================================

    function addFinding(
        type,
        severity,
        points,
        description
    ) {

        findings.push({

            type:
                type,

            severity:
                severity,

            score:
                points,

            description:
                description

        });


        score += points;

    }


    // ==================================================
    // PREPARE EMAIL DATA
    // ==================================================

    const body =
        String(
            email.body || ""
        ).toLowerCase();


    const subject =
        String(
            email.subject || ""
        ).toLowerCase();


    const sender =
        String(
            email.sender || ""
        ).toLowerCase();


    const replyTo =
        String(
            email.replyTo ||
            email.headers?.["reply-to"] ||
            ""
        ).toLowerCase();


    const urls =
        Array.isArray(email.urls)
            ? email.urls
            : [];


    const bodyIPs =
        Array.isArray(email.ips)
            ? email.ips
            : [];


    const headerIPs =
        Array.isArray(email.headerIPs)
            ? email.headerIPs
            : [];


    const received =
        Array.isArray(email.received)
            ? email.received
            : [];


    const attachments =
        Array.isArray(email.attachments)
            ? email.attachments
            : [];


    const authentication =
        email.authentication || {
            spf: "NOT CONFIGURED",
            dkim: "NOT CONFIGURED",
            dmarc: "NOT CONFIGURED",
            details: []
        };


    const linkMismatches =
        Array.isArray(email.linkMismatches)
            ? email.linkMismatches
            : [];


    // ==================================================
    // 1. URGENCY DETECTION
    // ==================================================

    const urgencyWords = [

        "urgent",

        "immediately",

        "as soon as possible",

        "action required",

        "act now",

        "important",

        "warning",

        "alert",

        "deadline",

        "last chance",

        "within 24 hours"

    ];


    const matchedUrgency =
        urgencyWords.filter(
            word =>
                body.includes(word) ||
                subject.includes(word)
        );


    if (
        matchedUrgency.length > 0
    ) {

        addFinding(

            "URGENCY_LANGUAGE",

            "MEDIUM",

            10,

            `Email uses pressure or urgency language: ${matchedUrgency.join(", ")}.`

        );

    }


    // ==================================================
    // 2. CREDENTIAL REQUEST
    // ==================================================

    const credentialWords = [

        "password",

        "username",

        "login",

        "sign in",

        "signin",

        "credentials",

        "verify your account",

        "verify your identity",

        "authentication",

        "authenticate",

        "one-time password",

        "otp"

    ];


    const matchedCredentials =
        credentialWords.filter(
            word =>
                body.includes(word) ||
                subject.includes(word)
        );


    if (
        matchedCredentials.length > 0
    ) {

        addFinding(

            "CREDENTIAL_REQUEST",

            "HIGH",

            20,

            `Email requests or discusses sensitive account credentials: ${matchedCredentials.join(", ")}.`

        );

    }


    // ==================================================
    // 3. ACCOUNT THREAT
    // ==================================================

    const accountThreatWords = [

        "account suspended",

        "account will be suspended",

        "account blocked",

        "account disabled",

        "account terminated",

        "permanently suspended",

        "access will be removed",

        "account locked"

    ];


    const matchedAccountThreats =
        accountThreatWords.filter(
            word =>
                body.includes(word) ||
                subject.includes(word)
        );


    if (
        matchedAccountThreats.length > 0
    ) {

        addFinding(

            "ACCOUNT_THREAT",

            "HIGH",

            20,

            "Email threatens account suspension, blocking, or loss of access."

        );

    }


    // ==================================================
    // 4. FINANCIAL / BANKING LANGUAGE
    // ==================================================

    const financialWords = [

        "bank",

        "banking",

        "payment",

        "credit card",

        "debit card",

        "invoice",

        "transaction",

        "refund",

        "wallet",

        "money",

        "financial",

        "upi",

        "account number"

    ];


    const matchedFinancial =
        financialWords.filter(
            word =>
                body.includes(word) ||
                subject.includes(word)
        );


    if (
        matchedFinancial.length > 0
    ) {

        addFinding(

            "FINANCIAL_LANGUAGE",

            "MEDIUM",

            15,

            `Email contains financial or payment-related language: ${matchedFinancial.join(", ")}.`

        );

    }


    // ==================================================
    // 5. URL DETECTION
    // ==================================================

    if (
        urls.length > 0
    ) {

        addFinding(

            "URL_DETECTED",

            "LOW",

            5,

            `Email contains ${urls.length} URL${urls.length > 1 ? "s" : ""}.`

        );

    }


    // ==================================================
    // 6. URL + DOMAIN INTELLIGENCE
    // ==================================================

    const urlAnalysis =
        analyzeURLs(
            urls
        );


    // Add URL-specific findings to
    // the overall threat score.

    urlAnalysis.forEach(
        analysis => {

            analysis.findings.forEach(
                finding => {

                    addFinding(

                        `URL_${finding.type}`,

                        finding.severity,

                        finding.score,

                        `${finding.description} URL: ${analysis.url}`

                    );

                }
            );

        }
    );


    // ==================================================
    // 7. URL SUMMARY FINDING
    // ==================================================

    const highRiskURLs =
        urlAnalysis.filter(
            item =>
                item.riskScore >= 70
        );


    if (
        highRiskURLs.length > 0
    ) {

        findings.push({

            type:
                "HIGH_RISK_URL",

            severity:
                "HIGH",

            score:
                0,

            description:
                `${highRiskURLs.length} URL${highRiskURLs.length > 1 ? "s were" : " was"} classified as high risk by URL intelligence analysis.`

        });

    }


    // ==================================================
    // 8. URL SHORTENER
    // ==================================================

    // This is kept as a separate email-level finding
    // so the investigator can quickly see it.

    const shortenerPattern =
        /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|shorturl\.at|rebrand\.ly)/i;


    const hasShortener =
        urls.some(
            url =>
                shortenerPattern.test(
                    url
                )
        );


    if (
        hasShortener
    ) {

        // URL intelligence already contributes
        // risk points for this condition.
        // Therefore we only create an explanatory
        // finding here without adding points.

        findings.push({

            type:
                "URL_SHORTENER_PRESENT",

            severity:
                "MEDIUM",

            score:
                0,

            description:
                "A URL-shortening service was detected. The shortened link may hide its final destination."

        });

    }


    // ==================================================
    // 9. BODY IP DETECTION
    // ==================================================

    if (
        bodyIPs.length > 0
    ) {

        addFinding(

            "IP_ADDRESS_IN_BODY",

            "MEDIUM",

            15,

            `Email body contains ${bodyIPs.length} IP address${bodyIPs.length > 1 ? "es" : ""}.`

        );

    }


    // ==================================================
    // 10. HEADER IP DETECTION
    // ==================================================

    if (
        headerIPs.length > 0
    ) {

        addFinding(

            "HEADER_IP_DETECTED",

            "LOW",

            5,

            `Email headers contain ${headerIPs.length} IP address${headerIPs.length > 1 ? "es" : ""}.`

        );

    }


    // ==================================================
    // 11. REPLY-TO MISMATCH
    // ==================================================

    if (
        replyTo &&
        sender
    ) {

        // Extract email addresses.

        const senderMatch =
            sender.match(
                /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i
            );


        const replyMatch =
            replyTo.match(
                /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i
            );


        if (
            senderMatch &&
            replyMatch
        ) {

            const senderEmail =
                senderMatch[0]
                    .toLowerCase();


            const replyEmail =
                replyMatch[0]
                    .toLowerCase();


            if (
                senderEmail !==
                replyEmail
            ) {

                addFinding(

                    "REPLY_TO_MISMATCH",

                    "HIGH",

                    25,

                    `The sender address (${senderEmail}) differs from the Reply-To address (${replyEmail}).`

                );

            }

        }

    }


    // ==================================================
    // 12. CLICK / VERIFY LANGUAGE
    // ==================================================

    const actionWords = [

        "click here",

        "click the link",

        "verify now",

        "verify immediately",

        "confirm now",

        "login here",

        "sign in here",

        "click below"

    ];


    const matchedActions =
        actionWords.filter(
            word =>
                body.includes(word) ||
                subject.includes(word)
        );


    if (
        matchedActions.length > 0
    ) {

        addFinding(

            "SUSPICIOUS_ACTION_LANGUAGE",

            "MEDIUM",

            10,

            `Email encourages the recipient to take an immediate action: ${matchedActions.join(", ")}.`

        );

    }


    // ==================================================
    // 13. BRAND IMPERSONATION IN SENDER
    // ==================================================

    const knownBrands = [

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

        "dropbox"

    ];


    const suspiciousSenderPatterns = [

        "micros0ft",

        "paypa1",

        "g00gle",

        "amaz0n",

        "app1e",

        "faceb00k",

        "netf1ix"

    ];


    const senderBrandDetected =
        knownBrands.some(
            brand =>
                sender.includes(
                    brand
                )
        );


    const senderLookalikeDetected =
        suspiciousSenderPatterns.some(
            pattern =>
                sender.includes(
                    pattern
                )
        );


    if (
        senderLookalikeDetected
    ) {

        addFinding(

            "SENDER_LOOKALIKE_DOMAIN",

            "HIGH",

            30,

            "Sender information contains a lookalike spelling commonly associated with brand impersonation."

        );

    }

    else if (
        senderBrandDetected &&
        urls.length > 0
    ) {

        findings.push({

            type:
                "BRAND_NAME_IN_SENDER",

            severity:
                "LOW",

            score:
                0,

            description:
                "Sender contains a recognizable brand name. Further authentication and domain analysis should be performed."

        });

    }


    // ==================================================
    // 14. SUSPICIOUS DOMAIN PATTERN
    // ==================================================

    const suspiciousDomainPattern =
        /\.(xyz|top|click|tk|ml|ga|cf|gq|pw|zip|review|country|work|party|date|win)(\/|$)/i;


    const suspiciousDomain =
        urls.some(
            url =>
                suspiciousDomainPattern.test(
                    url
                )
        );


    if (
        suspiciousDomain
    ) {

        // URL intelligence already calculates
        // the actual URL risk points.
        // This is only an explanatory email-level
        // indicator.

        findings.push({

            type:
                "SUSPICIOUS_DOMAIN_TLD",

            severity:
                "MEDIUM",

            score:
                0,

            description:
                "At least one URL uses a domain extension frequently encountered in suspicious or disposable domains."

        });

    }


    // ==================================================
    // 15. MULTIPLE RECEIVED HOPS
    // ==================================================

    if (
        received.length >= 3
    ) {

        findings.push({

            type:
                "MULTIPLE_MAIL_HOPS",

            severity:
                "LOW",

            score:
                0,

            description:
                `The email contains ${received.length} Received-header hops. These can be reconstructed for infrastructure analysis.`

        });

    }


    // ==================================================
    // 16. ATTACHMENT ANALYSIS
    // ==================================================

    const dangerousExtensions = [
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta",
        ".cpl", ".msc", ".jar", ".iso", ".img", ".docm",
        ".xlsm", ".pptm", ".dll"
    ];

    const archiveExtensions = [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".cab"
    ];

    const attachmentsAnalysis = [];

    attachments.forEach(att => {
        const name = (att.filename || "").toLowerCase();
        const ext = name.includes(".") ? name.substring(name.lastIndexOf(".")) : "";
        let risk = "LOW RISK";
        let isDangerous = false;

        const doubleExtMatch = name.match(/\.(pdf|docx?|xlsx?|txt|jpg|png)\.(exe|scr|bat|vbs|js|cmd|hta|iso)$/i);
        if (doubleExtMatch) {
            isDangerous = true;
            risk = "HIGH RISK";
            addFinding(
                "DOUBLE_EXTENSION_ATTACHMENT",
                "HIGH",
                40,
                `Attachment "${att.filename}" uses a deceptive double extension to disguise an executable payload.`
            );
        } else if (dangerousExtensions.includes(ext)) {
            isDangerous = true;
            risk = "HIGH RISK";
            addFinding(
                "DANGEROUS_ATTACHMENT",
                "HIGH",
                35,
                `Attachment "${att.filename}" has a high-risk executable or script extension (${ext}).`
            );
        } else if (archiveExtensions.includes(ext)) {
            risk = "MEDIUM RISK";
            addFinding(
                "ARCHIVE_ATTACHMENT",
                "MEDIUM",
                15,
                `Attachment "${att.filename}" is an archive file (${ext}) commonly used to deliver hidden malware.`
            );
        }

        attachmentsAnalysis.push({
            filename: att.filename,
            contentType: att.contentType,
            size: att.size,
            checksum: att.checksum,
            risk: risk,
            isDangerous: isDangerous
        });
    });


    // ==================================================
    // 17. EMAIL AUTHENTICATION CHECKS (SPF / DKIM / DMARC)
    // ==================================================

    if (authentication.spf === "FAIL") {
        addFinding(
            "SPF_AUTHENTICATION_FAILED",
            "HIGH",
            25,
            "Sender domain failed SPF (Sender Policy Framework) authentication. The transmitting server is unauthorized."
        );
    } else if (authentication.spf === "SOFTFAIL") {
        addFinding(
            "SPF_SOFTFAIL",
            "MEDIUM",
            15,
            "SPF returned softfail: sending host is not explicitly authorized for this domain."
        );
    }

    if (authentication.dkim === "FAIL") {
        addFinding(
            "DKIM_VERIFICATION_FAILED",
            "HIGH",
            20,
            "DKIM signature verification failed: message headers or body may have been modified in transit."
        );
    }

    if (authentication.dmarc === "FAIL") {
        addFinding(
            "DMARC_POLICY_FAILED",
            "HIGH",
            25,
            "DMARC alignment check failed against the domain publishing policy."
        );
    }

    if (senderBrandDetected && (authentication.spf === "FAIL" || authentication.spf === "SOFTFAIL" || authentication.spf === "NOT CONFIGURED")) {
        if (!senderLookalikeDetected) {
            addFinding(
                "UNAUTHENTICATED_BRAND_SENDER",
                "HIGH",
                25,
                "Email claims to originate from a major brand but lacks valid cryptographic authentication (SPF/DKIM)."
            );
        }
    }


    // ==================================================
    // 18. LINK SPOOFING (DISPLAY TEXT VS HREF)
    // ==================================================

    if (linkMismatches.length > 0) {
        linkMismatches.forEach(mismatch => {
            addFinding(
                "LINK_DESTINATION_MISMATCH",
                "HIGH",
                30,
                `Deceptive link detected: displayed text indicates "${mismatch.displayedDomain}", but destination URL points to "${mismatch.actualDomain}".`
            );
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
    // DETERMINE VERDICT
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
    // DETERMINE CONFIDENCE
    // ==================================================

    let confidence;


    if (
        findings.length >= 7
    ) {

        confidence =
            95;

    }

    else if (
        findings.length >= 5
    ) {

        confidence =
            90;

    }

    else if (
        findings.length >= 3
    ) {

        confidence =
            85;

    }

    else if (
        findings.length >= 1
    ) {

        confidence =
            70;

    }

    else {

        confidence =
            50;

    }


    // ==================================================
    // RETURN COMPLETE THREAT ANALYSIS
    // ==================================================

    return {

        score:
            score,

        verdict:
            verdict,

        confidence:
            confidence,

        findings:
            findings,

        indicators:
            findings,

        urlAnalysis:
            urlAnalysis,

        attachmentsAnalysis:
            attachmentsAnalysis,

        authentication:
            authentication

    };

}


// ======================================================
// EXPORT
// ======================================================

module.exports = {

    analyzeThreat

};