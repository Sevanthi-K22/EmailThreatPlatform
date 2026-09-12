/*
===========================================================
EMAIL THREAT INTELLIGENCE PLATFORM
DASHBOARD JAVASCRIPT ENGINE
===========================================================

Features:
1. Session verification and authentication guard
2. Drag-and-drop & file input .eml analysis
3. Dynamic Threat Score bar & verdict badge styling
4. Suspicious indicators with severity styling
5. Email forensics (Identity, Authentication SPF/DKIM/DMARC, Attachments)
6. Extracted URLs and IP infrastructure lists
7. Header relay path forensics
8. URL & domain intelligence with risk findings tags
9. IP infrastructure geolocation & forensic disclaimer
10. Interactive Threat Relationship Graph with SVG connector lines
11. Multi-tab email evidence viewer (Plaintext, HTML, Raw Headers)
12. Sidebar smooth navigation and active section tracking
13. Investigation report export (Print/PDF)
14. New Scan reset functionality
===========================================================
*/

// Global store for latest analysis data
let latestAnalysis = null;

// =========================================================
// 1. SESSION GUARD & INITIALIZATION
// =========================================================

function checkSession() {
    const session = sessionStorage.getItem("investigator_session");
    if (!session) {
        window.location.href = "index.html";
    }
}

// =========================================================
// 2. ANALYZE EMAIL
// =========================================================

async function analyzeEmail() {
    console.log("Analyze Email initiated.");

    const fileInput = document.getElementById("emailFile");
    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        alert("Please select an .eml file first.");
        return;
    }

    const file = fileInput.files[0];
    processFileAnalysis(file);
}

async function processFileAnalysis(file) {
    if (!file.name.toLowerCase().endsWith(".eml")) {
        alert("Please upload a valid .eml file.");
        return;
    }

    const analyzeBtn = document.getElementById("analyzeButton");
    if (analyzeBtn) {
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = "⏳ Analyzing...";
    }

    setAnalysisMessage("Analyzing email evidence... please wait.", "#2867ed");

    const formData = new FormData();
    formData.append("email", file);

    try {
        // Try relative endpoint first, fallback to localhost:3000
        const endpoint = window.location.origin.includes("3000")
            ? "/api/analyze"
            : "http://localhost:3000/api/analyze";

        const response = await fetch(endpoint, {
            method: "POST",
            body: formData
        });

        const rawText = await response.text();
        let data;

        try {
            data = JSON.parse(rawText);
        } catch (jsonError) {
            throw new Error("Invalid response received from backend server.");
        }

        if (!response.ok) {
            throw new Error(data.message || data.error || "Email analysis failed.");
        }

        latestAnalysis = data;
        console.log("Analysis completed:", data);

        displayResults(data);
        setAnalysisMessage("Analysis completed successfully: " + file.name, "#168b51");

    } catch (error) {
        console.error("Analysis error:", error);
        setAnalysisMessage(error.message || "Could not connect to backend server.", "#d52f2f");
    } finally {
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = "🔍 Analyze Email";
        }
    }
}

// =========================================================
// 3. STATUS MESSAGE
// =========================================================

function setAnalysisMessage(text, color) {
    let msg = document.getElementById("analysisMessage");
    if (msg) {
        msg.textContent = text;
        msg.style.color = color || "#2867ed";
    }
}

// =========================================================
// 4. DISPLAY ALL RESULTS
// =========================================================

function displayResults(data) {
    if (!data) return;

    displayThreatOverview(data);
    displayEmailInformation(data);
    displayAuthentication(data.authentication);
    displayAttachments(data.attachments, data.attachmentsAnalysis);
    displayIndicators(data.findings || data.indicators || []);
    displayURLs(data.urls || []);
    displayIPs(data.allIPs || getCombinedIPs(data));
    displayHeaderPath(data.received || []);
    displayHeaderIPs(data.headerIPs || []);
    displayURLIntelligence(data.urlAnalysis || []);
    displayIPInfrastructure(data.ipAnalysis || []);
    displayEmailContent(data);
    displayThreatGraph(data);
}

// =========================================================
// 5. THREAT OVERVIEW
// =========================================================

function displayThreatOverview(data) {
    const score = Number(data.threatScore ?? data.score ?? 0);
    const cappedScore = Math.max(0, Math.min(100, score));

    setText("threatScore", cappedScore);

    // Score bar fill and color
    const scoreBar = document.getElementById("scoreBar");
    if (scoreBar) {
        scoreBar.style.width = cappedScore + "%";
        if (cappedScore >= 70) {
            scoreBar.style.backgroundColor = "#d52f2f";
        } else if (cappedScore >= 40) {
            scoreBar.style.backgroundColor = "#e69500";
        } else {
            scoreBar.style.backgroundColor = "#168b51";
        }
    }

    // Verdict and badge styling
    const verdict = String(data.verdict || "LOW RISK").toUpperCase();
    const verdictEl = document.getElementById("verdict");
    if (verdictEl) {
        verdictEl.textContent = verdict;
        verdictEl.className = "stat-value verdict-value " + getVerdictClass(verdict);
    }

    // Verdict description
    const descEl = document.getElementById("verdictDescription");
    if (descEl) {
        if (verdict.includes("HIGH")) {
            descEl.textContent = "High-risk threat detected. Immediate containment advised.";
            descEl.style.color = "#d52f2f";
        } else if (verdict.includes("MEDIUM")) {
            descEl.textContent = "Suspicious characteristics detected. Further verification required.";
            descEl.style.color = "#bd7700";
        } else {
            descEl.textContent = "No significant threats identified. Normal email traffic.";
            descEl.style.color = "#168b51";
        }
    }

    // Confidence
    const confidence = data.confidence ?? 0;
    setText("confidence", confidence);

    // Counts
    const urls = Array.isArray(data.urls) ? data.urls : [];
    setText("urlCount", urls.length);

    const ips = getCombinedIPs(data);
    setText("ipCount", ips.length);
}

function getCombinedIPs(data) {
    const bodyIPs = Array.isArray(data.ips) ? data.ips : [];
    const headerIPs = Array.isArray(data.headerIPs) ? data.headerIPs : [];
    return [...new Set([...bodyIPs, ...headerIPs])];
}

// =========================================================
// 6. EMAIL INFORMATION
// =========================================================

function displayEmailInformation(data) {
    const email = data.email || data;

    setText("sender", email.sender || "---");
    setText("recipient", email.recipient || "---");
    setText("subject", email.subject || "---");
    setText("emailDate", formatDate(email.date));
    setText("messageId", email.messageId || "---");
    setText("replyTo", email.replyTo || "---");
}

// =========================================================
// 7. EMAIL AUTHENTICATION (SPF, DKIM, DMARC)
// =========================================================

function displayAuthentication(auth) {
    const authData = auth || { spf: "NOT CONFIGURED", dkim: "NOT CONFIGURED", dmarc: "NOT CONFIGURED", details: [] };

    updateAuthBadge("spfStatus", authData.spf);
    updateAuthBadge("dkimStatus", authData.dkim);
    updateAuthBadge("dmarcStatus", authData.dmarc);

    const detailsContainer = document.getElementById("authDetails");
    if (detailsContainer) {
        detailsContainer.innerHTML = "";
        if (Array.isArray(authData.details) && authData.details.length > 0) {
            authData.details.forEach(d => {
                const item = document.createElement("div");
                item.className = "auth-detail-item";
                item.textContent = d;
                detailsContainer.appendChild(item);
            });
        }
    }
}

function updateAuthBadge(elementId, status) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const val = String(status || "NONE").toUpperCase();
    el.textContent = val;

    if (val.includes("PASS")) {
        el.className = "auth-badge pass";
    } else if (val.includes("FAIL")) {
        el.className = "auth-badge fail";
    } else if (val.includes("SOFTFAIL")) {
        el.className = "auth-badge softfail";
    } else {
        el.className = "auth-badge neutral";
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
        const isDangerous = att.isDangerous || String(att.risk || "").includes("HIGH");
        card.className = "attachment-card" + (isDangerous ? " dangerous" : "");

        const info = document.createElement("div");
        info.className = "attachment-info";

        const icon = document.createElement("span");
        icon.className = "attachment-icon";
        icon.textContent = isDangerous ? "⚠️" : "📎";

        const details = document.createElement("div");
        const name = document.createElement("div");
        name.className = "attachment-name";
        name.textContent = att.filename || "unnamed";

        const meta = document.createElement("div");
        meta.className = "attachment-meta";
        const sizeStr = att.size ? formatBytes(att.size) : "Unknown size";
        meta.textContent = "Type: " + (att.contentType || "Unknown") + " | Size: " + sizeStr;

        details.appendChild(name);
        details.appendChild(meta);

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

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// =========================================================
// 9. SUSPICIOUS INDICATORS
// =========================================================

function displayIndicators(findings) {
    const container = document.getElementById("indicators");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(findings) || findings.length === 0) {
        container.innerHTML = '<p class="empty-state">No suspicious indicators detected.</p>';
        return;
    }

    const list = document.createElement("div");
    list.className = "indicator-list";

    findings.forEach((finding, index) => {
        const item = document.createElement("div");
        item.className = "indicator";

        const left = document.createElement("div");
        left.className = "indicator-left";

        let code = finding.type || finding.code || ("INDICATOR_" + (index + 1));
        let desc = finding.description || finding.message || "Suspicious indicator identified.";
        let points = Number(finding.score ?? finding.points ?? 0);
        let severity = finding.severity || (points >= 20 ? "HIGH" : points >= 10 ? "MEDIUM" : "LOW");
        let icon = getSeverityIcon(severity);

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
// 10. EXTRACTED URLS & IPS (FIXED ID QUERIES)
// =========================================================

function displayURLs(urls) {
    // Check both lowercase and uppercase variations to prevent ID mismatch
    const container = document.getElementById("extractedUrls") || document.getElementById("extractedURLs");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(urls) || urls.length === 0) {
        container.innerHTML = '<div class="empty-state">No URLs detected.</div>';
        return;
    }

    const list = document.createElement("div");
    list.className = "item-list";

    urls.forEach(url => {
        const item = document.createElement("div");
        item.className = "list-item";
        item.innerHTML = "🔗 <strong>" + escapeHtml(url) + "</strong>";
        list.appendChild(item);
    });

    container.appendChild(list);
}

function displayIPs(ips) {
    const container = document.getElementById("extractedIPs");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(ips) || ips.length === 0) {
        container.innerHTML = '<div class="empty-state">No IP addresses detected.</div>';
        return;
    }

    const list = document.createElement("div");
    list.className = "item-list";

    ips.forEach(ip => {
        const item = document.createElement("div");
        item.className = "list-item";
        item.innerHTML = "🌐 <strong>" + escapeHtml(ip) + "</strong>";
        list.appendChild(item);
    });

    container.appendChild(list);
}

function displayHeaderIPs(ips) {
    const container = document.getElementById("headerIPs");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(ips) || ips.length === 0) {
        container.innerHTML = '<div class="empty-state">No header IPs detected.</div>';
        return;
    }

    const list = document.createElement("div");
    list.className = "item-list";

    ips.forEach(ip => {
        const item = document.createElement("div");
        item.className = "list-item";
        item.innerHTML = "💻 <strong>" + escapeHtml(ip) + "</strong> (Received header origin)";
        list.appendChild(item);
    });

    container.appendChild(list);
}

function displayHeaderPath(received) {
    // Check both relayPath and headerPath to prevent ID mismatch
    const container = document.getElementById("relayPath") || document.getElementById("headerPath");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(received) || received.length === 0) {
        container.innerHTML = '<div class="empty-state">No header relay information available.</div>';
        return;
    }

    const list = document.createElement("div");
    list.className = "relay-list";

    const path = [...received].reverse();

    path.forEach((hop, idx) => {
        const item = document.createElement("div");
        item.className = "relay-item";
        item.innerHTML = "<strong>Hop " + (idx + 1) + ":</strong> " + escapeHtml(String(hop));
        list.appendChild(item);
    });

    container.appendChild(list);
}

// =========================================================
// 11. URL & DOMAIN INTELLIGENCE
// =========================================================

function displayURLIntelligence(analyses) {
    const container = document.getElementById("urlAnalysis");
    if (!container) return;

    container.innerHTML = "";

    if (!Array.isArray(analyses) || analyses.length === 0) {
        container.innerHTML = '<div class="panel"><div class="empty-state">No URL intelligence available.</div></div>';
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "url-analysis-container";

    analyses.forEach(analysis => {
        const card = document.createElement("div");
        card.className = "url-analysis-card";

        // Header with Domain and Verdict
        const header = document.createElement("div");
        header.className = "url-analysis-header";

        const domainDiv = document.createElement("div");
        const domainTitle = document.createElement("div");
        domainTitle.className = "url-domain";
        domainTitle.textContent = analysis.domain || "Unknown Domain";

        const urlValue = document.createElement("div");
        urlValue.className = "url-value";
        urlValue.textContent = analysis.url;

        domainDiv.appendChild(domainTitle);
        domainDiv.appendChild(urlValue);

        const verdict = document.createElement("span");
        const verdictVal = analysis.verdict || "UNKNOWN";
        verdict.className = "url-verdict " + getVerdictClass(verdictVal);
        verdict.textContent = verdictVal;

        header.appendChild(domainDiv);
        header.appendChild(verdict);
        card.appendChild(header);

        // Details Grid (3 columns)
        const details = document.createElement("div");
        details.className = "url-details";

        details.appendChild(createUrlDetail("Protocol", analysis.protocol || "---"));
        details.appendChild(createUrlDetail("TLD Extension", analysis.tld ? ("." + analysis.tld) : "---"));
        details.appendChild(createUrlDetail("Risk Score", (analysis.riskScore ?? 0) + " / 100"));

        if (analysis.brand) {
            details.appendChild(createUrlDetail("Impersonated Brand", analysis.brand));
        }

        card.appendChild(details);

        // Findings tags
        if (Array.isArray(analysis.findings) && analysis.findings.length > 0) {
            const findingList = document.createElement("div");
            findingList.className = "finding-list";

            analysis.findings.forEach(f => {
                const tag = document.createElement("span");
                tag.className = "finding-tag";
                tag.textContent = typeof f === "string" ? f : (f.description || f.type || "Suspicious attribute");
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
// 12. IP INFRASTRUCTURE & GEOLOCATION
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
        ipTitle.textContent = "🌐 " + (analysis.ip || "Unknown IP");

        const status = document.createElement("span");
        status.className = "ip-status " + getIPStatusClass(analysis.status);
        status.textContent = analysis.status || "UNKNOWN";

        header.appendChild(ipTitle);
        header.appendChild(status);
        card.appendChild(header);

        // Status message if any
        if (analysis.message) {
            const msg = document.createElement("p");
            msg.className = "ip-message";
            msg.textContent = analysis.message;
            card.appendChild(msg);
        }

        // Details grid if successful
        if (String(analysis.status || "").toUpperCase() === "SUCCESS") {
            const grid = document.createElement("div");
            grid.className = "ip-detail-grid";

            grid.appendChild(createIPRow("Country", analysis.country));
            grid.appendChild(createIPRow("Region / City", (analysis.region || "") + ", " + (analysis.city || "")));
            grid.appendChild(createIPRow("ISP", analysis.isp));
            grid.appendChild(createIPRow("Organization", analysis.organization));
            grid.appendChild(createIPRow("Autonomous System", analysis.autonomousSystem || analysis.as));
            grid.appendChild(createIPRow("Coordinates", (analysis.latitude ?? "?") + ", " + (analysis.longitude ?? "?")));

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
// 13. EMAIL CONTENT & EVIDENCE VIEWER
// =========================================================

function displayEmailContent(data) {
    const bodyText = document.getElementById("emailBodyText");
    if (bodyText) {
        bodyText.textContent = data.body || "(No plaintext body found in email)";
    }

    const htmlFrame = document.getElementById("emailHtmlPreview");
    if (htmlFrame) {
        if (data.htmlBody) {
            htmlFrame.innerHTML = data.htmlBody;
        } else {
            htmlFrame.textContent = "(No HTML content found in email)";
        }
    }

    const headersText = document.getElementById("rawHeadersText");
    if (headersText) {
        if (data.headers && typeof data.headers === "object") {
            const headerLines = Object.entries(data.headers)
                .map(([k, v]) => k.toUpperCase() + ": " + v)
                .join("\n");
            headersText.textContent = headerLines || "(No headers available)";
        } else {
            headersText.textContent = "(No headers available)";
        }
    }
}

function switchContentTab(tabName) {
    const tabs = ["plain", "html", "headers"];
    tabs.forEach(t => {
        const btn = document.getElementById("tabBtn" + capitalize(t));
        const pane = document.getElementById("tab" + capitalize(t));
        if (btn) btn.classList.remove("active");
        if (pane) pane.classList.remove("active");
    });

    const activeBtn = document.getElementById("tabBtn" + capitalize(tabName));
    const activePane = document.getElementById("tab" + capitalize(tabName));
    if (activeBtn) activeBtn.classList.add("active");
    if (activePane) activePane.classList.add("active");
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// =========================================================
// 14. THREAT RELATIONSHIP GRAPH (CONNECTED WITH SVG LINES)
// =========================================================

function displayThreatGraph(data) {
    const container = document.getElementById("threatGraphContainer");
    if (!container) return;

    // Clear container
    container.innerHTML = "";

    const nodes = buildGraphNodes(data);

    // Create SVG overlay for connecting edges
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "threat-graph-svg");

    const emailNode = nodes.find(n => n.type === "email");

    if (emailNode) {
        nodes.forEach(node => {
            if (node !== emailNode) {
                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute("x1", emailNode.x + "%");
                line.setAttribute("y1", emailNode.y + "%");
                line.setAttribute("x2", node.x + "%");
                line.setAttribute("y2", node.y + "%");
                line.setAttribute("stroke", "#b8c9e0");
                line.setAttribute("stroke-width", "2");
                if (node.type === "url") {
                    line.setAttribute("stroke-dasharray", "4");
                }
                svg.appendChild(line);
            }
        });
    }

    container.appendChild(svg);

    // Create DOM node elements
    nodes.forEach(node => {
        const el = document.createElement("div");
        // CSS expects .graph-node.email, .graph-node.sender, .graph-node.url, .graph-node.ip
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

    // Central Email node
    nodes.push({
        id: "email-center",
        type: "email",
        label: "Suspicious Email",
        fullValue: data.fileName || "Email Evidence",
        x: 50,
        y: 45
    });

    // Sender Domain node (top-left)
    const sender = data.email?.sender || data.sender || "";
    const senderDomain = extractDomainFromEmail(sender);
    if (senderDomain) {
        nodes.push({
            id: "sender-domain",
            type: "sender",
            label: shortenText(senderDomain, 20),
            fullValue: senderDomain,
            x: 20,
            y: 20
        });
    }

    // Extracted URLs (right side)
    const urls = Array.isArray(data.urls) ? data.urls.slice(0, 3) : [];
    urls.forEach((url, i) => {
        nodes.push({
            id: "url-" + i,
            type: "url",
            label: shortenText(url, 22),
            fullValue: url,
            x: 80,
            y: 20 + i * 25
        });
    });

    // Extracted IP addresses (bottom-left)
    const ips = getCombinedIPs(data).slice(0, 3);
    ips.forEach((ip, i) => {
        nodes.push({
            id: "ip-" + i,
            type: "ip",
            label: ip,
            fullValue: ip,
            x: 22 + i * 24,
            y: 82
        });
    });

    return nodes;
}

function getGraphNodeIcon(type) {
    switch (type) {
        case "email": return "📧";
        case "sender": return "👤";
        case "url": return "🔗";
        case "ip": return "🌐";
        default: return "🔎";
    }
}

// =========================================================
// 15. NAVIGATION & SCROLL TRACKING
// =========================================================

function handleNavClick(event, sectionId) {
    if (event) event.preventDefault();

    const target = document.getElementById(sectionId);
    if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    updateActiveNavLink(sectionId);
}

function updateActiveNavLink(sectionId) {
    const navLinks = document.querySelectorAll(".nav-item");
    navLinks.forEach(link => {
        const href = link.getAttribute("href");
        if (href === ("#" + sectionId)) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });
}

function setupScrollSpy() {
    const sections = document.querySelectorAll("section[id]");
    window.addEventListener("scroll", () => {
        let current = "";
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 120;
            if (window.pageYOffset >= sectionTop) {
                current = section.getAttribute("id");
            }
        });
        if (current) {
            updateActiveNavLink(current);
        }
    });
}

// =========================================================
// 16. EXPORT REPORT & RESET INVESTIGATION
// =========================================================

function exportReport() {
    if (!latestAnalysis) {
        alert("Please analyze an email before exporting a report.");
        return;
    }
    window.print();
}

function resetInvestigation() {
    latestAnalysis = null;

    const fileInput = document.getElementById("emailFile");
    if (fileInput) fileInput.value = "";

    setAnalysisMessage("", "#1e3a8a");

    // Reset stats
    setText("threatScore", "---");
    const scoreBar = document.getElementById("scoreBar");
    if (scoreBar) scoreBar.style.width = "0%";

    const verdictEl = document.getElementById("verdict");
    if (verdictEl) {
        verdictEl.textContent = "---";
        verdictEl.className = "stat-value verdict-value";
    }

    setText("verdictDescription", "Awaiting email analysis");
    setText("confidence", "---");
    setText("urlCount", "---");
    setText("ipCount", "---");

    // Reset email info
    ["sender", "recipient", "subject", "emailDate", "messageId", "replyTo"].forEach(id => setText(id, "---"));

    // Reset panels
    updateAuthBadge("spfStatus", "NOT CHECKED");
    updateAuthBadge("dkimStatus", "NOT CHECKED");
    updateAuthBadge("dmarcStatus", "NOT CHECKED");

    ["indicators", "extractedUrls", "extractedURLs", "extractedIPs", "relayPath", "headerPath", "headerIPs", "urlAnalysis", "ipAnalysis", "attachmentsList", "authDetails"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<div class="empty-state">No analysis performed yet.</div>';
    });

    // Reset content viewer
    setText("emailBodyText", "No email analyzed yet.");
    setText("emailHtmlPreview", "No HTML content available.");
    setText("rawHeadersText", "No headers available.");

    // Reset graph
    const graphContainer = document.getElementById("threatGraphContainer");
    if (graphContainer) {
        graphContainer.innerHTML = '<div class="graph-empty" id="graphEmptyState"><div class="graph-icon">🕸️</div><h3>Threat Relationship Graph</h3><p>Analyze an email to visualize relationships between the sender, URLs and IP infrastructure.</p></div>';
    }
}

// =========================================================
// 17. DRAG & DROP SUPPORT
// =========================================================

function setupDragAndDrop() {
    const dropZone = document.querySelector(".upload-card");
    const fileInput = document.getElementById("emailFile");
    if (!dropZone || !fileInput) return;

    ["dragenter", "dragover"].forEach(evt => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("drag-over");
        });
    });

    ["dragleave", "drop"].forEach(evt => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("drag-over");
        });
    });

    dropZone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            fileInput.files = files;
            processFileAnalysis(files[0]);
        }
    });
}

// =========================================================
// 18. HELPERS & LOGOUT
// =========================================================

function setText(elementId, text) {
    const el = document.getElementById(elementId);
    if (el) el.textContent = text;
}

function formatDate(val) {
    if (!val) return "---";
    try {
        const d = new Date(val);
        return isNaN(d.getTime()) ? String(val) : d.toLocaleString();
    } catch (e) {
        return String(val);
    }
}

function shortenText(str, maxLen) {
    if (!str) return "";
    return str.length <= maxLen ? str : str.substring(0, maxLen - 3) + "...";
}

function extractDomainFromEmail(sender) {
    const match = String(sender || "").match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].toLowerCase() : "";
}

function getVerdictClass(verdict) {
    const v = String(verdict || "").toUpperCase();
    if (v.includes("HIGH")) return "verdict-high";
    if (v.includes("MEDIUM")) return "verdict-medium";
    return "verdict-low";
}

function getIPStatusClass(status) {
    const s = String(status || "").toUpperCase();
    if (s === "SUCCESS") return "status-success";
    if (s === "SKIPPED") return "status-skipped";
    return "status-error";
}

function escapeHtml(str) {
    return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function logout() {
    sessionStorage.removeItem("investigator_session");
    latestAnalysis = null;
    window.location.href = "index.html";
}

// =========================================================
// 19. PAGE LOAD LISTENER
// =========================================================

document.addEventListener("DOMContentLoaded", () => {
    checkSession();
    setupDragAndDrop();
    setupScrollSpy();

    const fileInput = document.getElementById("emailFile");
    if (fileInput) {
        fileInput.addEventListener("change", () => {
            if (fileInput.files && fileInput.files[0]) {
                setAnalysisMessage("File selected: " + fileInput.files[0].name + " — click Analyze to begin.", "#2867ed");
            }
        });
    }
});
