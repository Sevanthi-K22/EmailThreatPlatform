/* =========================================================
   EMAIL THREAT INTELLIGENCE PLATFORM
   PRODUCTION SOC DASHBOARD JAVASCRIPT ENGINE
   =========================================================

   Features:
   1. Session verification & authentication guard (checkSession / logout)
   2. Drag-and-drop & file selector for .eml evidence files
   3. Real API communication (POST /api/analyze with field "email")
   4. Live Threat Score meter & severity-driven verdict badges
   5. Email forensic metadata (Sender, Recipient, Subject, Date, Message-ID, Reply-To)
   6. Cryptographic authentication checks (SPF, DKIM, DMARC)
   7. Attachment forensics with danger flags for executable files
   8. Deep suspicious indicators with threat scoring and severity badges
   9. Extracted URLs and IP infrastructure discovery
   10. Header relay path transit hops (reverse chronological order)
   11. Multi-tab email evidence viewer (Plaintext, Sandboxed HTML, RFC 822 Headers)
   12. URL & Domain Intelligence with brand impersonation detection
   13. Infrastructure Geolocation with real ASN, ISP, City, and Country telemetry
   14. Dynamic SVG Threat Relationship Graph linking real email entities
   15. Investigation reset and print/PDF export capabilities
   ========================================================= */

"use strict";

// Store for latest analysis response
let latestAnalysis = null;
let isAnalyzing = false;

// =========================================================
// 1. INITIALIZATION & SESSION GUARD
// =========================================================

document.addEventListener("DOMContentLoaded", function () {
    console.log("SOC Dashboard Engine initialized.");

    // Enforce authentication
    checkSession();

    // Setup UI components
    setupNavigation();
    setupFileUpload();
    setupDragAndDrop();
    setupEvidenceTabs();
    setupScrollSpy();

    // Default tab
    switchContentTab("plain");
});

function checkSession() {
    const session = sessionStorage.getItem("investigator_session");
    if (!session) {
        console.warn("Unauthorized access: no active session found. Redirecting to login.");
        window.location.href = "index.html";
    }
}

function logout() {
    sessionStorage.removeItem("investigator_session");
    window.location.href = "index.html";
}

// =========================================================
// 2. FILE UPLOAD & DRAG-AND-DROP
// =========================================================

function setupFileUpload() {
    const fileInput = document.getElementById("emailFile");
    if (!fileInput) return;

    fileInput.addEventListener("change", function () {
        if (fileInput.files && fileInput.files.length > 0) {
            updateSelectedFileUI(fileInput.files[0]);
        }
    });
}

function updateSelectedFileUI(file) {
    const promptEl = document.getElementById("fileUploadPrompt");
    if (promptEl && file) {
        promptEl.innerHTML = "Selected file: <strong>" + escapeHtml(file.name) + "</strong> (" + formatBytes(file.size) + ")";
        promptEl.style.color = "#45b7ff";
    }
}

function setupDragAndDrop() {
    const dropZone = document.querySelector(".upload-card");
    const fileInput = document.getElementById("emailFile");
    if (!dropZone || !fileInput) return;

    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, function (e) {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("drag-over");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, function (e) {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("drag-over");
        }, false);
    });

    dropZone.addEventListener("drop", function (e) {
        const dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length > 0) {
            const file = dt.files[0];
            if (!file.name.toLowerCase().endsWith(".eml")) {
                showAnalysisMessage("Invalid file type. Only .eml files are supported.", "#ff5577");
                return;
            }

            try {
                fileInput.files = dt.files;
            } catch (err) {
                // If DataTransfer cannot be assigned to file input in some browsers
            }

            updateSelectedFileUI(file);
            processFileAnalysis(file);
        }
    }, false);
}

// =========================================================
// 3. API COMMUNICATION & ANALYSIS INITIATION
// =========================================================

async function analyzeEmail() {
    if (isAnalyzing) return;

    const fileInput = document.getElementById("emailFile");
    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        showAnalysisMessage("Please select or drop an .eml file first.", "#ffd166");
        return;
    }

    const file = fileInput.files[0];
    processFileAnalysis(file);
}

async function processFileAnalysis(file) {
    if (!file || !file.name.toLowerCase().endsWith(".eml")) {
        showAnalysisMessage("Please upload a valid .eml file.", "#ff5577");
        return;
    }

    isAnalyzing = true;
    setAnalyzeButtonState(true);
    showAnalysisMessage("Analyzing email evidence... querying threat engines.", "#258fff");

    // Form data with exact required field: "email"
    const formData = new FormData();
    formData.append("email", file, file.name);

    console.log("Uploading email using field: email");

    try {
        const endpoint = window.location.origin.includes(":3000")
            ? "/api/analyze"
            : "http://localhost:3000/api/analyze";

        const response = await fetch(endpoint, {
            method: "POST",
            body: formData
        });

        const contentType = response.headers.get("content-type") || "";
        let data;

        if (contentType.includes("application/json")) {
            data = await response.json();
        } else {
            const text = await response.text();
            try {
                data = JSON.parse(text);
            } catch (e) {
                throw new Error("Invalid response received from server: " + text.slice(0, 100));
            }
        }

        console.log("Backend response:", data);

        if (!response.ok) {
            throw new Error(data.message || data.error || ("Server returned HTTP " + response.status));
        }

        latestAnalysis = data;
        console.log("Final analysis response:", data);
        console.log("Displaying analysis:", data);

        displayResults(data);
        showAnalysisMessage("Analysis completed successfully: " + file.name, "#27e6a5");

    } catch (error) {
        console.error("Email analysis failed:", error);
        showAnalysisMessage(error.message || "Failed to communicate with analysis backend.", "#ff5577");
    } finally {
        isAnalyzing = false;
        setAnalyzeButtonState(false);
    }
}

function setAnalyzeButtonState(loading) {
    const btn = document.getElementById("analyzeButton");
    if (!btn) return;

    if (loading) {
        btn.disabled = true;
        btn.textContent = "⏳ Analyzing...";
    } else {
        btn.disabled = false;
        btn.textContent = "🔍 Analyze Email";
    }
}

function showAnalysisMessage(text, color) {
    const msg = document.getElementById("analysisMessage");
    if (msg) {
        msg.textContent = text;
        msg.style.color = color;
    }
}

// =========================================================
// 4. RESULT ORCHESTRATION
// =========================================================

function displayResults(data) {
    if (!data) return;

    displayThreatOverview(data);
    displayEmailInformation(data);
    displayAuthentication(data.authentication);
    displayAttachments(data.attachments, data.attachmentsAnalysis);
    displayIndicators(data.findings || data.indicators);
    displayForensics(data);
    displayEmailContent(data);
    displayURLIntelligence(data.urlAnalysis);
    displayIPInfrastructure(data.ipAnalysis);
    displayThreatGraph(data);

    scrollToResults();
}

function scrollToResults() {
    const target = document.getElementById("dashboard");
    if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
}

// =========================================================
// 5. THREAT OVERVIEW RENDERING
// =========================================================

function displayThreatOverview(data) {
    const rawScore = Number(data.threatScore ?? data.score ?? 0);
    const score = Math.max(0, Math.min(100, isNaN(rawScore) ? 0 : rawScore));

    // Threat Score
    setText("threatScore", score);

    // Score Bar width & severity styling
    const scoreBar = document.getElementById("scoreBar");
    if (scoreBar) {
        scoreBar.style.width = score + "%";
        if (score >= 70) {
            scoreBar.style.backgroundColor = "#ff5577";
        } else if (score >= 40) {
            scoreBar.style.backgroundColor = "#ffd166";
        } else {
            scoreBar.style.backgroundColor = "#27e6a5";
        }
    }

    // Verdict Badge
    const verdict = String(data.verdict || (score >= 70 ? "HIGH RISK" : score >= 40 ? "MEDIUM RISK" : "LOW RISK")).toUpperCase();
    const verdictEl = document.getElementById("verdict");
    if (verdictEl) {
        verdictEl.textContent = verdict;
        verdictEl.className = "stat-value verdict-value " + getVerdictClass(verdict);
    }

    // Verdict Description
    const descEl = document.getElementById("verdictDescription");
    if (descEl) {
        if (verdict.includes("HIGH") || verdict.includes("CRITICAL")) {
            descEl.textContent = "High-risk threat detected. Immediate containment advised.";
            descEl.style.color = "#ff5577";
        } else if (verdict.includes("MEDIUM") || verdict.includes("WARNING")) {
            descEl.textContent = "Suspicious characteristics detected. Further verification required.";
            descEl.style.color = "#ffd166";
        } else {
            descEl.textContent = "No significant threats identified. Normal email traffic.";
            descEl.style.color = "#27e6a5";
        }
    }

    // Confidence
    const confidence = Number(data.confidence ?? 0);
    setText("confidence", confidence);

    // URLs Count
    const urls = Array.isArray(data.urls) ? data.urls : [];
    setText("urlCount", urls.length);

    // IPs Count (combined body + header IPs)
    const allIPs = Array.isArray(data.allIPs)
        ? data.allIPs
        : [...new Set([...(data.ips || []), ...(data.headerIPs || [])])];
    setText("ipCount", allIPs.length);
}

// =========================================================
// 6. EMAIL INFORMATION FORENSICS
// =========================================================

function displayEmailInformation(data) {
    const email = data.email || {};

    setText("sender", email.sender || data.sender || "—");
    setText("recipient", email.recipient || data.recipient || "—");
    setText("subject", email.subject || data.subject || "—");
    setText("emailDate", email.date ? formatDate(email.date) : "—");
    setText("messageId", email.messageId || "—");
    setText("replyTo", email.replyTo || "—");
}

// =========================================================
// 7. AUTHENTICATION (SPF, DKIM, DMARC)
// =========================================================

function displayAuthentication(auth) {
    const authData = auth || {
        spf: "NOT CONFIGURED",
        dkim: "NOT CONFIGURED",
        dmarc: "NOT CONFIGURED",
        details: []
    };

    updateAuthBadge("spfStatus", authData.spf);
    updateAuthBadge("dkimStatus", authData.dkim);
    updateAuthBadge("dmarcStatus", authData.dmarc);

    const detailsEl = document.getElementById("authDetails");
    if (detailsEl) {
        if (Array.isArray(authData.details) && authData.details.length > 0) {
            detailsEl.textContent = authData.details.join("\n");
            detailsEl.classList.add("has-details");
        } else {
            detailsEl.textContent = "";
            detailsEl.classList.remove("has-details");
        }
    }
}

function updateAuthBadge(elementId, status) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const s = String(status || "NOT CONFIGURED").toUpperCase();
    el.textContent = s;

    el.className = "auth-badge";

    if (s.includes("PASS") || s.includes("SUCCESS") || s.includes("VALID")) {
        el.classList.add("pass", "status-success");
    } else if (s.includes("FAIL") || s.includes("REJECT") || s.includes("DANGER")) {
        el.classList.add("fail", "status-danger");
    } else {
        el.classList.add("neutral", "status-warning");
    }
}

// =========================================================
// 8. ATTACHMENTS FORENSICS
// =========================================================

function displayAttachments(attachments, analysis) {
    const container = document.getElementById("attachmentsList");
    if (!container) return;

    container.innerHTML = "";

    const items = Array.isArray(analysis) && analysis.length > 0
        ? analysis
        : (Array.isArray(attachments) ? attachments : []);

    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state">No attachments detected in this email.</div>';
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "attachments-container";

    items.forEach(att => {
        const card = document.createElement("div");
        const filename = att.filename || "unnamed_attachment";
        const isDangerous = Boolean(
            att.isDangerous ||
            String(att.risk || "").toUpperCase().includes("HIGH") ||
            /\.(exe|scr|vbs|bat|cmd|pif|js|wsf|iso|dll|ps1)$/i.test(filename)
        );

        card.className = "attachment-card" + (isDangerous ? " dangerous" : "");

        const info = document.createElement("div");
        info.className = "attachment-info";

        const icon = document.createElement("span");
        icon.className = "attachment-icon";
        icon.textContent = isDangerous ? "⚠️" : "📎";

        const details = document.createElement("div");
        const nameEl = document.createElement("div");
        nameEl.className = "attachment-name";
        nameEl.textContent = filename;

        const metaEl = document.createElement("div");
        metaEl.className = "attachment-meta";
        const sizeStr = att.size ? formatBytes(att.size) : "Unknown size";
        metaEl.textContent = "Type: " + (att.contentType || "application/octet-stream") + " • Size: " + sizeStr;

        details.appendChild(nameEl);
        details.appendChild(metaEl);

        info.appendChild(icon);
        info.appendChild(details);

        const badge = document.createElement("span");
        badge.className = "attachment-badge " + (isDangerous ? "dangerous" : "safe");
        badge.textContent = isDangerous ? "HIGH RISK FILE" : "NORMAL ATTACHMENT";

        card.appendChild(info);
        card.appendChild(badge);
        wrapper.appendChild(card);
    });

    container.appendChild(wrapper);
}

// =========================================================
// 9. SUSPICIOUS INDICATORS & THREAT FACTORS
// =========================================================

function displayIndicators(findings) {
    const container = document.getElementById("indicators");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(findings) || findings.length === 0) {
        container.innerHTML = '<div class="empty-state">No suspicious indicators detected. Email traffic appears normal.</div>';
        return;
    }

    const list = document.createElement("div");
    list.className = "indicator-list";

    findings.forEach((finding, index) => {
        const item = document.createElement("div");
        const points = Number(finding.score ?? finding.points ?? 0);
        const severity = String(finding.severity || (points >= 20 ? "HIGH" : points >= 10 ? "MEDIUM" : "LOW")).toUpperCase();

        item.className = "indicator " + (severity.includes("HIGH") ? "high" : severity.includes("MEDIUM") ? "medium" : "low");

        const left = document.createElement("div");
        left.className = "indicator-left";

        const code = finding.type || finding.code || ("INDICATOR_" + (index + 1));
        const desc = finding.description || finding.message || "Suspicious anomaly detected.";
        const icon = getSeverityIcon(severity);

        const codeSpan = document.createElement("span");
        codeSpan.className = "indicator-code";
        codeSpan.textContent = icon + " " + code;

        const nameSpan = document.createElement("span");
        nameSpan.className = "indicator-name";
        nameSpan.textContent = desc;

        left.appendChild(codeSpan);
        left.appendChild(nameSpan);

        const scoreSpan = document.createElement("span");
        scoreSpan.className = "indicator-score";
        scoreSpan.textContent = points > 0 ? ("+" + points + " pts") : "INFO";

        item.appendChild(left);
        item.appendChild(scoreSpan);
        list.appendChild(item);
    });

    container.appendChild(list);
}

function getSeverityIcon(severity) {
    const s = String(severity || "").toUpperCase();
    if (s.includes("HIGH") || s.includes("CRITICAL")) return "🚨";
    if (s.includes("MEDIUM") || s.includes("WARNING")) return "⚠️";
    return "🔍";
}

// =========================================================
// 10. FORENSIC LISTS (URLS, IPS, RELAY PATH, HEADER IPS)
// =========================================================

function displayForensics(data) {
    // 1. Extracted URLs
    const urlsContainer = document.getElementById("extractedUrls");
    if (urlsContainer) {
        urlsContainer.innerHTML = "";
        const urls = Array.isArray(data.urls) ? data.urls : [];
        if (urls.length === 0) {
            urlsContainer.innerHTML = '<div class="empty-state">No URLs detected.</div>';
        } else {
            const list = document.createElement("div");
            list.className = "item-list";
            urls.forEach(url => {
                const item = document.createElement("div");
                item.className = "list-item";
                item.innerHTML = "🔗 <code>" + escapeHtml(url) + "</code>";
                list.appendChild(item);
            });
            urlsContainer.appendChild(list);
        }
    }

    // 2. Extracted IPs (Body)
    const ipsContainer = document.getElementById("extractedIPs");
    if (ipsContainer) {
        ipsContainer.innerHTML = "";
        const ips = Array.isArray(data.ips) ? data.ips : [];
        if (ips.length === 0) {
            ipsContainer.innerHTML = '<div class="empty-state">No IP addresses detected in email body.</div>';
        } else {
            const list = document.createElement("div");
            list.className = "item-list";
            ips.forEach(ip => {
                const item = document.createElement("div");
                item.className = "list-item";
                item.innerHTML = "🌐 <code>" + escapeHtml(ip) + "</code>";
                list.appendChild(item);
            });
            ipsContainer.appendChild(list);
        }
    }

    // 3. Email Relay Path (Hops)
    const relayContainer = document.getElementById("relayPath");
    if (relayContainer) {
        relayContainer.innerHTML = "";
        const received = Array.isArray(data.received) ? data.received : [];
        if (received.length === 0) {
            relayContainer.innerHTML = '<div class="empty-state">No header relay information available.</div>';
        } else {
            const list = document.createElement("div");
            list.className = "relay-list";
            // Reverse so Hop 1 is the original sender
            const hops = [...received].reverse();
            hops.forEach((hop, idx) => {
                const item = document.createElement("div");
                item.className = "relay-item";
                item.innerHTML = "<strong>Hop " + (idx + 1) + ":</strong> " + escapeHtml(String(hop));
                list.appendChild(item);
            });
            relayContainer.appendChild(list);
        }
    }

    // 4. Header IPs
    const headerIPsContainer = document.getElementById("headerIPs");
    if (headerIPsContainer) {
        headerIPsContainer.innerHTML = "";
        const headerIPs = Array.isArray(data.headerIPs) ? data.headerIPs : [];
        if (headerIPs.length === 0) {
            headerIPsContainer.innerHTML = '<div class="empty-state">No header IP addresses detected.</div>';
        } else {
            const list = document.createElement("div");
            list.className = "item-list";
            headerIPs.forEach(ip => {
                const item = document.createElement("div");
                item.className = "list-item";
                item.innerHTML = "💻 <code>" + escapeHtml(ip) + "</code> <span style='color:#7890a8;font-size:11px;'>(Received header origin)</span>";
                list.appendChild(item);
            });
            headerIPsContainer.appendChild(list);
        }
    }
}

// =========================================================
// 11. EMAIL EVIDENCE & CONTENT VIEWER (TABS & SANDBOX)
// =========================================================

function displayEmailContent(data) {
    // 1. Plain-text body
    const bodyEl = document.getElementById("emailBodyText");
    if (bodyEl) {
        bodyEl.textContent = data.body && String(data.body).trim()
            ? data.body
            : "(No plaintext body found in email)";
    }

    // 2. Sandboxed HTML Preview (Securely isolated iframe, no scripts allowed)
    const htmlContainer = document.getElementById("emailHtmlPreview");
    if (htmlContainer) {
        htmlContainer.innerHTML = "";

        if (data.htmlBody && String(data.htmlBody).trim()) {
            const iframe = document.createElement("iframe");
            iframe.className = "email-preview-iframe";
            // Strict sandbox: no scripts, no top navigation, isolated origin
            iframe.setAttribute("sandbox", "");
            iframe.setAttribute("title", "Email HTML Preview");
            iframe.srcdoc = String(data.htmlBody);
            htmlContainer.appendChild(iframe);
        } else {
            const empty = document.createElement("div");
            empty.className = "empty-message";
            empty.textContent = "(No HTML content found in email)";
            htmlContainer.appendChild(empty);
        }
    }

    // 3. Raw RFC 822 Headers
    const headersEl = document.getElementById("rawHeadersText");
    if (headersEl) {
        if (data.headers && typeof data.headers === "object") {
            const lines = Object.entries(data.headers).map(([k, v]) => {
                return k.toUpperCase() + ": " + (typeof v === "object" ? JSON.stringify(v) : v);
            });
            headersEl.textContent = lines.join("\n") || "(No headers available)";
        } else {
            headersEl.textContent = "(No headers available)";
        }
    }
}

function setupEvidenceTabs() {
    const tabs = ["plain", "html", "headers"];
    tabs.forEach(tabKey => {
        const btnId = "tabBtn" + capitalize(tabKey);
        const btn = document.getElementById(btnId);
        if (btn) {
            btn.addEventListener("click", () => switchContentTab(tabKey));
        }
    });
}

function switchContentTab(tabName) {
    const tabs = ["plain", "html", "headers"];
    tabs.forEach(t => {
        const btn = document.getElementById("tabBtn" + capitalize(t));
        const pane = document.getElementById("tab" + capitalize(t));
        if (btn) {
            btn.classList.toggle("active", t === tabName);
        }
        if (pane) {
            pane.classList.toggle("active", t === tabName);
        }
    });
}

// =========================================================
// 12. URL & DOMAIN INTELLIGENCE
// =========================================================

function displayURLIntelligence(analyses) {
    const container = document.getElementById("urlAnalysis");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(analyses) || analyses.length === 0) {
        container.innerHTML = '<div class="panel"><div class="empty-state">No URL intelligence available for this email.</div></div>';
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "url-analysis-container";

    analyses.forEach(analysis => {
        const card = document.createElement("div");
        card.className = "url-analysis-card";

        // Header (Domain & Verdict)
        const header = document.createElement("div");
        header.className = "url-analysis-header";

        const domainDiv = document.createElement("div");
        const domainTitle = document.createElement("div");
        domainTitle.className = "url-domain";
        domainTitle.textContent = analysis.domain || "Unknown Host";

        const urlValue = document.createElement("div");
        urlValue.className = "url-value";
        urlValue.textContent = analysis.url || "—";

        domainDiv.appendChild(domainTitle);
        domainDiv.appendChild(urlValue);

        const verdict = document.createElement("span");
        const verdictVal = String(analysis.verdict || "UNKNOWN").toUpperCase();
        verdict.className = "url-verdict " + (verdictVal.includes("HIGH") ? "high" : verdictVal.includes("MEDIUM") ? "medium" : "low");
        verdict.textContent = verdictVal;

        header.appendChild(domainDiv);
        header.appendChild(verdict);
        card.appendChild(header);

        // Details Grid
        const details = document.createElement("div");
        details.className = "url-details";

        details.appendChild(createUrlDetail("Protocol", analysis.protocol ? analysis.protocol.toUpperCase() : "—"));
        details.appendChild(createUrlDetail("TLD Extension", analysis.tld ? ("." + analysis.tld) : "—"));
        details.appendChild(createUrlDetail("Risk Score", (analysis.riskScore ?? 0) + " / 100"));

        if (analysis.brand) {
            details.appendChild(createUrlDetail("Target Brand Spoofing", analysis.brand.toUpperCase()));
        }

        card.appendChild(details);

        // Findings tags
        if (Array.isArray(analysis.findings) && analysis.findings.length > 0) {
            const findingList = document.createElement("div");
            findingList.className = "finding-list";

            analysis.findings.forEach(f => {
                const tag = document.createElement("span");
                tag.className = "finding-tag";
                tag.textContent = typeof f === "string" ? f : (f.description || f.type || "Suspicious URL pattern");
                findingList.appendChild(tag);
            });

            card.appendChild(findingList);
        }

        wrapper.appendChild(card);
    });

    container.appendChild(wrapper);
}

function createUrlDetail(label, value) {
    const div = document.createElement("div");
    div.className = "url-detail";
    div.innerHTML = "<strong>" + escapeHtml(label) + "</strong><span>" + escapeHtml(String(value)) + "</span>";
    return div;
}

// =========================================================
// 13. IP INFRASTRUCTURE & GEOLOCATION
// =========================================================

function displayIPInfrastructure(analyses) {
    const container = document.getElementById("ipAnalysis");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(analyses) || analyses.length === 0) {
        container.innerHTML = '<div class="panel"><div class="empty-state">No IP infrastructure geolocation available.</div></div>';
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "ip-analysis-container";

    analyses.forEach(analysis => {
        const card = document.createElement("div");
        card.className = "ip-analysis-card";

        // Header
        const header = document.createElement("div");
        header.className = "ip-analysis-header";

        const ipTitle = document.createElement("div");
        ipTitle.className = "ip-address";
        ipTitle.innerHTML = "🌐 <span>" + escapeHtml(analysis.ip || "Unknown IP") + "</span>";

        const status = document.createElement("span");
        const statusVal = String(analysis.status || "UNKNOWN").toUpperCase();
        status.className = "ip-status " + (statusVal === "SUCCESS" ? "success" : statusVal === "PRIVATE" ? "private" : "unknown");
        status.textContent = statusVal === "SUCCESS" ? "PUBLIC IP (RESOLVED)" : statusVal;

        header.appendChild(ipTitle);
        header.appendChild(status);
        card.appendChild(header);

        // Status Message
        if (analysis.message) {
            const msg = document.createElement("p");
            msg.className = "ip-message";
            msg.textContent = analysis.message;
            card.appendChild(msg);
        }

        // Details Grid for Resolved Geolocation
        if (statusVal === "SUCCESS") {
            const grid = document.createElement("div");
            grid.className = "ip-detail-grid";

            grid.appendChild(createIPRow("Country", (analysis.country || "Unknown") + (analysis.countryCode ? (" (" + analysis.countryCode + ")") : "")));
            grid.appendChild(createIPRow("Region / City", (analysis.region || "") + (analysis.city ? (", " + analysis.city) : "")));
            grid.appendChild(createIPRow("ISP", analysis.isp || "Unknown"));
            grid.appendChild(createIPRow("Organization", analysis.organization || "Unknown"));
            grid.appendChild(createIPRow("Autonomous System (ASN)", analysis.autonomousSystem || analysis.as || "Unknown"));

            const coords = (analysis.latitude !== null && analysis.latitude !== undefined && analysis.longitude !== null && analysis.longitude !== undefined)
                ? (analysis.latitude + ", " + analysis.longitude)
                : "Unavailable";
            grid.appendChild(createIPRow("Coordinates (Lat, Lon)", coords));

            if (analysis.timezone) {
                grid.appendChild(createIPRow("Timezone", analysis.timezone));
            }

            card.appendChild(grid);
        }

        wrapper.appendChild(card);
    });

    container.appendChild(wrapper);
}

function createIPRow(label, value) {
    const div = document.createElement("div");
    div.className = "ip-detail-row";
    div.innerHTML = "<strong>" + escapeHtml(label) + "</strong><span>" + escapeHtml(String(value || "Unknown")) + "</span>";
    return div;
}

// =========================================================
// 14. THREAT RELATIONSHIP GRAPH (SVG CONNECTORS & NODES)
// =========================================================

function displayThreatGraph(data) {
    const container = document.getElementById("threatGraphContainer");
    const emptyState = document.getElementById("graphEmptyState");
    if (!container) return;

    if (!data) {
        if (emptyState) emptyState.style.display = "flex";
        return;
    }

    if (emptyState) emptyState.style.display = "none";

    // Clear previous rendered SVG and nodes (keep empty state element)
    const oldSvg = container.querySelector(".threat-graph-svg");
    if (oldSvg) oldSvg.remove();
    container.querySelectorAll(".graph-node").forEach(node => node.remove());

    const nodes = buildGraphNodes(data);
    const emailNode = nodes.find(n => n.type === "email");

    // 1. Create SVG Canvas for Edge Lines
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "threat-graph-svg");

    if (emailNode) {
        nodes.forEach(node => {
            if (node !== emailNode) {
                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute("x1", emailNode.x + "%");
                line.setAttribute("y1", emailNode.y + "%");
                line.setAttribute("x2", node.x + "%");
                line.setAttribute("y2", node.y + "%");
                line.setAttribute("class", "graph-edge " + (node.edgeType || node.type));
                svg.appendChild(line);
            }
        });
    }

    // If there's an IP and Geo node, connect IP to Geo
    const ipNode = nodes.find(n => n.type === "ip");
    const geoNode = nodes.find(n => n.type === "geo");
    if (ipNode && geoNode) {
        const geoLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
        geoLine.setAttribute("x1", ipNode.x + "%");
        geoLine.setAttribute("y1", ipNode.y + "%");
        geoLine.setAttribute("x2", geoNode.x + "%");
        geoLine.setAttribute("y2", geoNode.y + "%");
        geoLine.setAttribute("class", "graph-edge geo");
        svg.appendChild(geoLine);
    }

    container.appendChild(svg);

    // 2. Create DOM Node Badges
    nodes.forEach(node => {
        const el = document.createElement("div");
        el.className = "graph-node " + node.type;
        el.style.left = node.x + "%";
        el.style.top = node.y + "%";
        el.title = node.fullValue || node.label;

        const icon = document.createElement("span");
        icon.className = "graph-node-icon";
        icon.textContent = getGraphNodeIcon(node.type);

        const label = document.createElement("span");
        label.className = "graph-node-label";
        label.textContent = node.label;

        el.appendChild(icon);
        el.appendChild(label);
        container.appendChild(el);
    });
}

function buildGraphNodes(data) {
    const nodes = [];

    // Central Email Node (center)
    nodes.push({
        id: "node-email",
        type: "email",
        label: shortenText(data.fileName || "Email Evidence", 22),
        fullValue: data.fileName || "Suspicious Email Evidence",
        x: 50,
        y: 48
    });

    // Sender Domain Node (Top-Left)
    const sender = (data.email && data.email.sender) || data.sender || "";
    const senderDomain = extractDomainFromEmail(sender);
    if (senderDomain) {
        nodes.push({
            id: "node-sender",
            type: "sender",
            label: shortenText(senderDomain, 20),
            fullValue: sender || senderDomain,
            x: 20,
            y: 20
        });
    }

    // Extracted URLs / Domains (Right Column)
    const urls = Array.isArray(data.urls) ? data.urls.slice(0, 3) : [];
    urls.forEach((url, i) => {
        let domain = "";
        try {
            domain = new URL(url).hostname;
        } catch (e) {
            domain = shortenText(url, 18);
        }
        nodes.push({
            id: "node-url-" + i,
            type: "url",
            edgeType: "url",
            label: shortenText(domain || url, 20),
            fullValue: url,
            x: 80,
            y: 18 + i * 26
        });
    });

    // Infrastructure IP Addresses (Bottom-Left)
    const allIPs = Array.isArray(data.allIPs)
        ? data.allIPs
        : [...new Set([...(data.ips || []), ...(data.headerIPs || [])])];
    const ipList = allIPs.slice(0, 2);

    ipList.forEach((ip, i) => {
        nodes.push({
            id: "node-ip-" + i,
            type: "ip",
            edgeType: "ip",
            label: ip,
            fullValue: ip,
            x: 22 + i * 26,
            y: 78
        });
    });

    // Geolocation / ASN Node (Bottom-Right)
    const ipAnalysis = Array.isArray(data.ipAnalysis) ? data.ipAnalysis : [];
    const resolvedGeo = ipAnalysis.find(item => item.status === "SUCCESS" && item.country);
    if (resolvedGeo) {
        const geoText = resolvedGeo.country + (resolvedGeo.city ? (", " + resolvedGeo.city) : "");
        nodes.push({
            id: "node-geo",
            type: "geo",
            edgeType: "geo",
            label: shortenText(geoText, 22),
            fullValue: geoText + (resolvedGeo.isp ? (" | " + resolvedGeo.isp) : ""),
            x: 78,
            y: 80
        });
    }

    return nodes;
}

function getGraphNodeIcon(type) {
    switch (type) {
        case "email": return "📧";
        case "sender": return "👤";
        case "url": return "🔗";
        case "ip": return "🌐";
        case "geo": return "🌍";
        default: return "🔍";
    }
}

// =========================================================
// 15. RESET & EXPORT REPORT
// =========================================================

function resetInvestigation() {
    latestAnalysis = null;
    isAnalyzing = false;

    // Clear file input
    const fileInput = document.getElementById("emailFile");
    if (fileInput) fileInput.value = "";

    const promptEl = document.getElementById("fileUploadPrompt");
    if (promptEl) {
        promptEl.textContent = "Drag and drop your .eml file here, or browse files on your device.";
        promptEl.style.color = "";
    }

    // Reset message
    showAnalysisMessage("", "");

    // Reset Overview
    setText("threatScore", "---");
    const scoreBar = document.getElementById("scoreBar");
    if (scoreBar) {
        scoreBar.style.width = "0%";
        scoreBar.style.backgroundColor = "#27e6a5";
    }

    const verdictEl = document.getElementById("verdict");
    if (verdictEl) {
        verdictEl.textContent = "---";
        verdictEl.className = "stat-value verdict-value";
    }

    setText("verdictDescription", "Awaiting email analysis");
    setText("confidence", "---");
    setText("urlCount", "---");
    setText("ipCount", "---");

    // Reset Email Info
    ["sender", "recipient", "subject", "emailDate", "messageId", "replyTo"].forEach(id => {
        setText(id, "---");
    });

    // Reset Auth
    updateAuthBadge("spfStatus", "NOT CHECKED");
    updateAuthBadge("dkimStatus", "NOT CHECKED");
    updateAuthBadge("dmarcStatus", "NOT CHECKED");
    const authDetails = document.getElementById("authDetails");
    if (authDetails) {
        authDetails.textContent = "";
        authDetails.classList.remove("has-details");
    }

    // Reset Forensic Lists
    const emptyMap = {
        "attachmentsList": '<div class="empty-state">No attachments detected.</div>',
        "indicators": '<div class="empty-state">No analysis performed yet.</div>',
        "extractedUrls": '<div class="empty-state">No URLs detected.</div>',
        "extractedIPs": '<div class="empty-state">No IP addresses detected.</div>',
        "relayPath": '<div class="empty-state">No header information available.</div>',
        "headerIPs": '<div class="empty-state">No header IPs detected.</div>',
        "urlAnalysis": '<div class="panel"><div class="empty-state">No URL analysis available yet.</div></div>',
        "ipAnalysis": '<div class="panel"><div class="empty-state">No IP infrastructure analysis available yet.</div></div>'
    };

    Object.entries(emptyMap).forEach(([id, html]) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = html;
    });

    // Reset Content Tabs
    setText("emailBodyText", "No email analyzed yet.");
    const htmlPreview = document.getElementById("emailHtmlPreview");
    if (htmlPreview) htmlPreview.innerHTML = '<div class="empty-message">No HTML content available.</div>';
    setText("rawHeadersText", "No headers available.");
    switchContentTab("plain");

    // Reset Graph
    const graphContainer = document.getElementById("threatGraphContainer");
    if (graphContainer) {
        const oldSvg = graphContainer.querySelector(".threat-graph-svg");
        if (oldSvg) oldSvg.remove();
        graphContainer.querySelectorAll(".graph-node").forEach(node => node.remove());
        const emptyState = document.getElementById("graphEmptyState");
        if (emptyState) emptyState.style.display = "flex";
    }

    console.log("Investigation reset to baseline state.");
}

function exportReport() {
    window.print();
}

// =========================================================
// 16. NAVIGATION & SCROLL TRACKING
// =========================================================

function setupNavigation() {
    const navLinks = document.querySelectorAll(".nav-item");
    navLinks.forEach(link => {
        link.addEventListener("click", function (e) {
            const href = link.getAttribute("href");
            if (href && href.startsWith("#")) {
                e.preventDefault();
                const sectionId = href.substring(1);
                handleNavClick(e, sectionId);
            }
        });
    });
}

function handleNavClick(event, sectionId) {
    if (event && typeof event.preventDefault === "function") {
        event.preventDefault();
    }

    const section = document.getElementById(sectionId);
    if (section) {
        section.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    updateActiveNavLink(sectionId);
}

function updateActiveNavLink(sectionId) {
    const navLinks = document.querySelectorAll(".nav-item");
    navLinks.forEach(link => {
        const href = link.getAttribute("href");
        if (href === "#" + sectionId) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });
}

function setupScrollSpy() {
    const sections = ["dashboard", "emailForensics", "emailContent", "urlIntelligence", "geoLocation", "threatGraph"];
    window.addEventListener("scroll", () => {
        const scrollPos = window.scrollY + 120;
        for (let i = sections.length - 1; i >= 0; i--) {
            const el = document.getElementById(sections[i]);
            if (el && el.offsetTop <= scrollPos) {
                updateActiveNavLink(sections[i]);
                break;
            }
        }
    }, { passive: true });
}

// =========================================================
// 17. UTILITY FUNCTIONS
// =========================================================

function setText(elementId, text) {
    const el = document.getElementById(elementId);
    if (el) {
        el.textContent = (text === null || text === undefined || text === "") ? "—" : String(text);
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatDate(val) {
    if (!val) return "—";
    try {
        const d = new Date(val);
        if (!isNaN(d.getTime())) {
            return d.toUTCString();
        }
    } catch (e) {}
    return String(val);
}

function shortenText(str, maxLen) {
    if (!str) return "";
    const s = String(str);
    if (s.length <= maxLen) return s;
    return s.substring(0, maxLen - 2) + "..";
}

function extractDomainFromEmail(sender) {
    if (!sender) return "";
    const match = sender.match(/@([a-zA-Z0-9.-]+)/);
    return match ? match[1].toLowerCase() : "";
}

function getVerdictClass(verdict) {
    const v = String(verdict || "").toUpperCase();
    if (v.includes("HIGH") || v.includes("CRITICAL")) return "high";
    if (v.includes("MEDIUM") || v.includes("WARNING")) return "medium";
    return "low";
}

function capitalize(str) {
    if (!str) return "";
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}