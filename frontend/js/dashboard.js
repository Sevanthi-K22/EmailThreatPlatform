/* =========================================================
   EMAIL THREAT INTELLIGENCE - DASHBOARD.JS
   ---------------------------------------------------------
   Application functionality for the redesigned SOC dashboard.
   Backend/API logic is preserved.
   ========================================================= */

"use strict";


/* =========================================================
   GLOBAL STATE
   ========================================================= */

let currentAnalysisData = null;
let currentFile = null;
let isAnalyzing = false;


/* =========================================================
   DOM READY
   ========================================================= */

document.addEventListener("DOMContentLoaded", function () {
    console.log("Dashboard JavaScript loaded.");

    checkSession();
    setupNavigation();
    setupFileUpload();
    setupDragAndDrop();
    setupEvidenceTabs();
    setupScrollSpy();

    switchContentTab("plain");

    console.log("Dashboard initialized successfully.");
});


/* =========================================================
   SESSION
   ========================================================= */

function checkSession() {
    const session = sessionStorage.getItem(
        "investigator_session"
    );

    if (!session) {
        console.warn(
            "No investigator session found."
        );
    }
}


/* =========================================================
   NAVIGATION
   ========================================================= */

function handleNavClick(
    eventOrSectionId,
    possibleSectionId
) {
    let sectionId;

    if (
        eventOrSectionId &&
        typeof eventOrSectionId.preventDefault ===
            "function"
    ) {
        eventOrSectionId.preventDefault();
        sectionId = possibleSectionId;
    } else {
        sectionId = eventOrSectionId;
    }

    if (!sectionId) {
        console.warn(
            "No navigation section supplied."
        );
        return;
    }

    const section =
        document.getElementById(sectionId);

    if (!section) {
        console.warn(
            "Navigation section not found:",
            sectionId
        );
        return;
    }

    section.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

    activateNavigationItem(sectionId);
}


function activateNavigationItem(sectionId) {
    const navItems =
        document.querySelectorAll(".nav-item");

    navItems.forEach(function (item) {
        item.classList.remove("active");

        const href =
            item.getAttribute("href");

        const dataTarget =
            item.getAttribute("data-target");

        if (
            dataTarget === sectionId ||
            href === "#" + sectionId
        ) {
            item.classList.add("active");
        }
    });
}


function setupNavigation() {
    const navItems =
        document.querySelectorAll(".nav-item");

    navItems.forEach(function (item) {

        const hasInlineHandler =
            item.getAttribute("onclick");

        if (hasInlineHandler) {
            return;
        }

        item.addEventListener(
            "click",
            function (event) {
                event.preventDefault();

                const dataTarget =
                    item.getAttribute(
                        "data-target"
                    );

                const href =
                    item.getAttribute("href");

                let target = dataTarget;

                if (
                    !target &&
                    href &&
                    href.startsWith("#")
                ) {
                    target =
                        href.substring(1);
                }

                if (target) {
                    handleNavClick(
                        event,
                        target
                    );
                }
            }
        );
    });

    activateNavigationItem("dashboard");
}


/* =========================================================
   FILE UPLOAD
   ========================================================= */

function setupFileUpload() {
    const fileInput =
        document.getElementById(
            "emailFile"
        );

    if (!fileInput) {
        console.warn(
            "emailFile input not found."
        );
        return;
    }

    fileInput.addEventListener(
        "change",
        function () {

            if (
                !fileInput.files ||
                fileInput.files.length === 0
            ) {
                return;
            }

            const file =
                fileInput.files[0];

            if (
                !file.name
                    .toLowerCase()
                    .endsWith(".eml")
            ) {
                fileInput.value = "";

                showAnalysisMessage(
                    "Please select a valid .eml email file.",
                    "error"
                );

                return;
            }

            currentFile = file;

            console.log(
                "Selected file:",
                file.name
            );

            updateSelectedFileUI(file);
        }
    );
}


function updateSelectedFileUI(file) {
    const message =
        document.getElementById(
            "analysisMessage"
        );

    if (!message) {
        return;
    }

    message.textContent =
        "Selected: " + file.name;

    message.classList.remove(
        "success",
        "error",
        "loading",
        "info"
    );

    message.classList.add(
        "file-selected"
    );
}


/* =========================================================
   DRAG & DROP
   ========================================================= */

function setupDragAndDrop() {
    const uploadCard =
        document.querySelector(
            ".upload-card"
        );

    const fileInput =
        document.getElementById(
            "emailFile"
        );

    if (
        !uploadCard ||
        !fileInput
    ) {
        return;
    }

    uploadCard.addEventListener(
        "dragover",
        function (event) {
            event.preventDefault();

            uploadCard.classList.add(
                "drag-over"
            );
        }
    );

    uploadCard.addEventListener(
        "dragleave",
        function () {
            uploadCard.classList.remove(
                "drag-over"
            );
        }
    );

    uploadCard.addEventListener(
        "drop",
        function (event) {
            event.preventDefault();

            uploadCard.classList.remove(
                "drag-over"
            );

            const files =
                event.dataTransfer.files;

            if (
                !files ||
                files.length === 0
            ) {
                return;
            }

            const file =
                files[0];

            if (
                !file.name
                    .toLowerCase()
                    .endsWith(".eml")
            ) {
                showAnalysisMessage(
                    "Please select a valid .eml email file.",
                    "error"
                );

                return;
            }

            try {
                const dataTransfer =
                    new DataTransfer();

                dataTransfer.items.add(file);

                fileInput.files =
                    dataTransfer.files;

            } catch (error) {
                console.warn(
                    "Could not assign dropped file:",
                    error
                );
            }

            currentFile = file;

            updateSelectedFileUI(file);

            console.log(
                "Dropped file:",
                file.name
            );
        }
    );
}


/* =========================================================
   ANALYZE EMAIL
   ========================================================= */

async function analyzeEmail() {

    if (isAnalyzing) {
        return;
    }

    const fileInput =
        document.getElementById(
            "emailFile"
        );

    if (!fileInput) {
        console.error(
            "emailFile element was not found."
        );

        return;
    }

    if (
        !fileInput.files ||
        fileInput.files.length === 0
    ) {
        showAnalysisMessage(
            "Please select an .eml file first.",
            "error"
        );

        return;
    }

    const file =
        fileInput.files[0];

    if (
        !file.name
            .toLowerCase()
            .endsWith(".eml")
    ) {
        showAnalysisMessage(
            "Only .eml files are supported.",
            "error"
        );

        return;
    }

    currentFile = file;
    isAnalyzing = true;

    setAnalyzeButtonState(true);

    showAnalysisMessage(
        "Analyzing email. Please wait...",
        "loading"
    );

    try {

        const result =
            await processFileAnalysis(file);

        currentAnalysisData =
            result;

        console.log(
            "Final analysis response:",
            result
        );

        displayResults(result);

        showAnalysisMessage(
            "Analysis completed successfully.",
            "success"
        );

    } catch (error) {

        console.error(
            "Email analysis failed:",
            error
        );

        showAnalysisMessage(
            error.message ||
                "Email analysis failed.",
            "error"
        );

    } finally {

        isAnalyzing = false;

        setAnalyzeButtonState(
            false
        );
    }
}


/* =========================================================
   API ANALYSIS
   ========================================================= */

async function processFileAnalysis(file) {

    const endpoint =
        window.location.origin.includes(
            ":3000"
        )
            ? "/api/analyze"
            : "http://localhost:3000/api/analyze";

    const formData =
        new FormData();

    /*
       IMPORTANT:
       Backend expects:
       upload.single("email")
    */

    formData.append(
        "email",
        file,
        file.name
    );

    console.log(
        "Uploading email using field: email"
    );

    const response =
        await fetch(
            endpoint,
            {
                method: "POST",
                body: formData
            }
        );

    const contentType =
        response.headers.get(
            "content-type"
        ) || "";

    let data;

    if (
        contentType.includes(
            "application/json"
        )
    ) {
        data =
            await response.json();

    } else {

        const text =
            await response.text();

        try {
            data =
                JSON.parse(text);

        } catch {
            data = {
                message: text
            };
        }
    }

    console.log(
        "Backend response:",
        data
    );

    if (!response.ok) {
        throw new Error(
            data.message ||
            data.error ||
            "Server returned HTTP " +
                response.status
        );
    }

    return data;
}


/* =========================================================
   DISPLAY RESULTS
   ========================================================= */

function displayResults(data) {

    if (!data) {
        console.warn(
            "No analysis data received."
        );

        return;
    }

    console.log(
        "Displaying analysis:",
        data
    );

    const result =
        data.data ||
        data.result ||
        data.analysis ||
        data;

    currentAnalysisData =
        data;

    updateThreatOverview(result);
    updateEmailInformation(result);
    updateAuthentication(result);
    updateForensics(result);
    updateEmailEvidence(result);
    updateIntelligence(result);
    updateGeoLocation(result);
    updateThreatGraph(result);

    scrollToResults();
}


/* =========================================================
   THREAT OVERVIEW
   ========================================================= */

function updateThreatOverview(data) {

    const threatScore =
        getValue(
            data,
            [
                "threatScore",
                "threat_score",
                "score",
                "riskScore",
                "risk_score"
            ],
            null
        );

    const verdict =
        getValue(
            data,
            [
                "verdict",
                "classification",
                "threatVerdict"
            ],
            null
        );

    const confidence =
        getValue(
            data,
            [
                "confidence",
                "confidenceScore",
                "confidence_score"
            ],
            null
        );

    const urlCount =
        getValue(
            data,
            [
                "urlCount",
                "url_count",
                "urlsDetected"
            ],
            null
        );

    const ipCount =
        getValue(
            data,
            [
                "ipCount",
                "ip_count",
                "ipsDetected"
            ],
            null
        );

    setText(
        "threatScore",
        threatScore !== null
            ? formatScore(
                threatScore
            ) + " / 100"
            : "—"
    );

    setText(
        "verdict",
        verdict || "—"
    );

    setText(
        "confidence",
        confidence !== null
            ? formatConfidence(
                confidence
            ) + " %"
            : "—"
    );

    setText(
        "urlCount",
        urlCount !== null
            ? String(urlCount)
            : "—"
    );

    setText(
        "ipCount",
        ipCount !== null
            ? String(ipCount)
            : "—"
    );

    const scoreBar =
        document.getElementById(
            "scoreBar"
        );

    if (
        scoreBar &&
        threatScore !== null
    ) {

        let numericScore =
            parseFloat(
                threatScore
            );

        if (
            !Number.isNaN(
                numericScore
            )
        ) {

            numericScore =
                Math.max(
                    0,
                    Math.min(
                        100,
                        numericScore
                    )
                );

            scoreBar.style.width =
                numericScore + "%";
        }
    }

    const verdictDescription =
        getValue(
            data,
            [
                "verdictDescription",
                "verdict_description",
                "description",
                "summary"
            ],
            null
        );

    setText(
        "verdictDescription",
        verdictDescription ||
            "Analysis completed."
    );

    const verdictElement =
        document.getElementById(
            "verdict"
        );

    if (verdictElement) {

        verdictElement.classList.remove(
            "high",
            "medium",
            "low",
            "critical",
            "safe"
        );

        const normalized =
            String(
                verdict || ""
            ).toLowerCase();

        if (
            normalized.includes(
                "critical"
            )
        ) {

            verdictElement.classList.add(
                "critical"
            );

        } else if (
            normalized.includes(
                "high"
            )
        ) {

            verdictElement.classList.add(
                "high"
            );

        } else if (
            normalized.includes(
                "medium"
            ) ||
            normalized.includes(
                "suspicious"
            )
        ) {

            verdictElement.classList.add(
                "medium"
            );

        } else if (
            normalized.includes(
                "low"
            ) ||
            normalized.includes(
                "safe"
            ) ||
            normalized.includes(
                "clean"
            )
        ) {

            verdictElement.classList.add(
                "low"
            );
        }
    }
}


/* =========================================================
   EMAIL INFORMATION
   ========================================================= */

function updateEmailInformation(data) {

    const email =
        data.email ||
        data.emailInfo ||
        data.email_information ||
        data;

    setText(
        "sender",
        getValue(
            email,
            [
                "sender",
                "from",
                "senderEmail",
                "fromEmail"
            ],
            "—"
        )
    );

    setText(
        "recipient",
        getValue(
            email,
            [
                "recipient",
                "to",
                "recipientEmail",
                "toEmail"
            ],
            "—"
        )
    );

    setText(
        "subject",
        getValue(
            email,
            [
                "subject"
            ],
            "—"
        )
    );

    setText(
        "emailDate",
        getValue(
            email,
            [
                "emailDate",
                "date",
                "timestamp"
            ],
            "—"
        )
    );

    setText(
        "messageId",
        getValue(
            email,
            [
                "messageId",
                "message_id"
            ],
            "—"
        )
    );

    setText(
        "replyTo",
        getValue(
            email,
            [
                "replyTo",
                "reply_to"
            ],
            "—"
        )
    );
}


/* =========================================================
   AUTHENTICATION
   ========================================================= */

function updateAuthentication(data) {

    const auth =
        data.authentication ||
        data.auth ||
        data.emailAuthentication ||
        {};

    const spf =
        getValue(
            auth,
            [
                "spf",
                "spfStatus",
                "spf_status"
            ],
            getValue(
                data,
                [
                    "spf",
                    "spfStatus",
                    "spf_status"
                ],
                "NOT CONFIGURED"
            )
        );

    const dkim =
        getValue(
            auth,
            [
                "dkim",
                "dkimStatus",
                "dkim_status"
            ],
            getValue(
                data,
                [
                    "dkim",
                    "dkimStatus",
                    "dkim_status"
                ],
                "NOT CONFIGURED"
            )
        );

    const dmarc =
        getValue(
            auth,
            [
                "dmarc",
                "dmarcStatus",
                "dmarc_status"
            ],
            getValue(
                data,
                [
                    "dmarc",
                    "dmarcStatus",
                    "dmarc_status"
                ],
                "NOT CONFIGURED"
            )
        );

    updateAuthStatus(
        "spfStatus",
        spf
    );

    updateAuthStatus(
        "dkimStatus",
        dkim
    );

    updateAuthStatus(
        "dmarcStatus",
        dmarc
    );

    const details =
        getValue(
            auth,
            [
                "details",
                "description",
                "message"
            ],
            getValue(
                data,
                [
                    "authDetails",
                    "authenticationDetails"
                ],
                ""
            )
        );

    setText(
        "authDetails",
        details ||
            "No authentication details available."
    );
}


function updateAuthStatus(
    id,
    value
) {

    const element =
        document.getElementById(
            id
        );

    if (!element) {
        return;
    }

    element.textContent =
        formatStatus(
            value
        );

    element.classList.remove(
        "status-success",
        "status-warning",
        "status-danger",
        "success",
        "warning",
        "danger"
    );

    const normalized =
        String(
            value
        ).toLowerCase();

    if (
        normalized.includes("pass") ||
        normalized.includes("valid") ||
        normalized.includes("success")
    ) {

        element.classList.add(
            "status-success"
        );

    } else if (
        normalized.includes("fail") ||
        normalized.includes("invalid") ||
        normalized.includes("danger")
    ) {

        element.classList.add(
            "status-danger"
        );

    } else {

        element.classList.add(
            "status-warning"
        );
    }
}


/* =========================================================
   FORENSICS
   ========================================================= */

function updateForensics(data) {

    const attachments =
        getValue(
            data,
            [
                "attachments",
                "attachmentList"
            ],
            []
        );

    const indicators =
        getValue(
            data,
            [
                "indicators",
                "suspiciousIndicators",
                "findings"
            ],
            []
        );

    const urls =
        getValue(
            data,
            [
                "extractedUrls",
                "urls",
                "extracted_urls"
            ],
            []
        );

    const ips =
        getValue(
            data,
            [
                "extractedIPs",
                "ips",
                "ipAddresses",
                "extracted_ips"
            ],
            []
        );

    const relayPath =
        getValue(
            data,
            [
                "relayPath",
                "relay_path",
                "receivedPath"
            ],
            []
        );

    const headerIPs =
        getValue(
            data,
            [
                "headerIPs",
                "header_ips"
            ],
            []
        );

    renderList(
        "attachmentsList",
        attachments,
        "No attachments detected."
    );

    renderList(
        "indicators",
        indicators,
        "No suspicious indicators detected."
    );

    renderList(
        "extractedUrls",
        urls,
        "No URLs detected."
    );

    renderList(
        "extractedIPs",
        ips,
        "No IP addresses detected."
    );

    renderList(
        "relayPath",
        relayPath,
        "No relay information available."
    );

    renderList(
        "headerIPs",
        headerIPs,
        "No header IP addresses detected."
    );
}


/* =========================================================
   EMAIL EVIDENCE
   ========================================================= */

function updateEmailEvidence(data) {

    const plainText =
        getValue(
            data,
            [
                "body",
                "plainText",
                "plainBody",
                "textBody",
                "emailBodyText"
            ],
            ""
        );

    const htmlBody =
        getValue(
            data,
            [
                "htmlBody",
                "html",
                "emailHtml"
            ],
            ""
        );

    const rawHeaders =
        getValue(
            data,
            [
                "rawHeaders",
                "headers",
                "raw_headers"
            ],
            ""
        );

    setText(
        "emailBodyText",
        plainText ||
            "No plain-text body available."
    );

    setText(
        "rawHeadersText",
        rawHeaders ||
            "No raw headers available."
    );

    renderHtmlEmailPreview(
        htmlBody
    );
}


function renderHtmlEmailPreview(
    htmlBody
) {

    const container =
        document.getElementById(
            "emailHtmlPreview"
        );

    if (!container) {
        return;
    }

    container.innerHTML = "";

    if (
        !htmlBody ||
        String(
            htmlBody
        ).trim() === ""
    ) {

        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "empty-message";

        empty.textContent =
            "No HTML body available.";

        container.appendChild(
            empty
        );

        return;
    }

    const iframe =
        document.createElement(
            "iframe"
        );

    iframe.className =
        "email-preview-iframe";

    iframe.setAttribute(
        "sandbox",
        ""
    );

    iframe.setAttribute(
        "title",
        "Email HTML Preview"
    );

    iframe.style.width =
        "100%";

    iframe.style.height =
        "100%";

    iframe.style.minHeight =
        "360px";

    iframe.style.border =
        "0";

    iframe.style.background =
        "#ffffff";

    iframe.srcdoc =
        String(htmlBody);

    container.appendChild(
        iframe
    );
}


/* =========================================================
   EVIDENCE TABS
   ========================================================= */

function setupEvidenceTabs() {

    const plainButton =
        document.getElementById(
            "tabBtnPlain"
        );

    const htmlButton =
        document.getElementById(
            "tabBtnHtml"
        );

    const headersButton =
        document.getElementById(
            "tabBtnHeaders"
        );

    if (plainButton) {

        plainButton.addEventListener(
            "click",
            function () {
                switchContentTab(
                    "plain"
                );
            }
        );
    }

    if (htmlButton) {

        htmlButton.addEventListener(
            "click",
            function () {
                switchContentTab(
                    "html"
                );
            }
        );
    }

    if (headersButton) {

        headersButton.addEventListener(
            "click",
            function () {
                switchContentTab(
                    "headers"
                );
            }
        );
    }
}


function switchContentTab(
    tabName
) {

    const tabs = {
        plain: "tabPlain",
        html: "tabHtml",
        headers: "tabHeaders"
    };

    const buttons = {
        plain: "tabBtnPlain",
        html: "tabBtnHtml",
        headers: "tabBtnHeaders"
    };

    Object.keys(
        tabs
    ).forEach(
        function (key) {

            const tab =
                document.getElementById(
                    tabs[key]
                );

            const button =
                document.getElementById(
                    buttons[key]
                );

            if (tab) {

                tab.classList.remove(
                    "active"
                );

                tab.style.display =
                    "none";
            }

            if (button) {

                button.classList.remove(
                    "active"
                );
            }
        }
    );

    if (!tabs[tabName]) {
        tabName = "plain";
    }

    const selectedTab =
        document.getElementById(
            tabs[tabName]
        );

    const selectedButton =
        document.getElementById(
            buttons[tabName]
        );

    if (selectedTab) {

        selectedTab.classList.add(
            "active"
        );

        selectedTab.style.display =
            "block";
    }

    if (selectedButton) {

        selectedButton.classList.add(
            "active"
        );
    }
}


/* =========================================================
   URL + IP INTELLIGENCE
   ========================================================= */

function updateIntelligence(data) {

    const urlAnalysis =
        getValue(
            data,
            [
                "urlAnalysis",
                "urlIntelligence",
                "url_analysis"
            ],
            []
        );

    const ipAnalysis =
        getValue(
            data,
            [
                "ipAnalysis",
                "ipIntelligence",
                "ip_analysis"
            ],
            []
        );

    /*
       IMPORTANT FIX:
       This previously called renderAnalysis(),
       but the actual renderer in this file is
       renderIntelligence().
    */

    renderIntelligence(
        "urlAnalysis",
        urlAnalysis,
        "No URL intelligence available.",
        "url"
    );

    renderIntelligence(
        "ipAnalysis",
        ipAnalysis,
        "No IP intelligence available.",
        "ip"
    );
}


/* =========================================================
   INTELLIGENCE RENDERER
   ========================================================= */

function renderIntelligence(
    elementId,
    data,
    emptyMessage,
    type
) {

    const container =
        document.getElementById(
            elementId
        );

    if (!container) {
        return;
    }

    container.innerHTML = "";

    const panel =
        document.createElement(
            "div"
        );

    panel.className =
        "intelligence-panel";

    const normalized =
        normalizeAnalysisData(
            data
        );

    if (
        normalized.length === 0
    ) {

        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "empty-state";

        empty.textContent =
            emptyMessage;

        panel.appendChild(
            empty
        );

        container.appendChild(
            panel
        );

        return;
    }

    normalized.forEach(
        function (item, index) {

            const card =
                createIntelligenceCard(
                    item,
                    type,
                    index
                );

            panel.appendChild(
                card
            );
        }
    );

    container.appendChild(
        panel
    );
}


/* =========================================================
   NORMALIZE INTELLIGENCE DATA
   ========================================================= */

function normalizeAnalysisData(
    data
) {

    if (
        data === null ||
        data === undefined ||
        data === ""
    ) {
        return [];
    }

    if (Array.isArray(data)) {
        return data;
    }

    if (
        typeof data === "object"
    ) {

        const possibleArrays = [
            "results",
            "data",
            "urls",
            "ips",
            "items",
            "records",
            "resultsData"
        ];

        for (
            const key of possibleArrays
        ) {

            if (
                Array.isArray(
                    data[key]
                )
            ) {
                return data[key];
            }
        }

        return [data];
    }

    return [data];
}


/* =========================================================
   INTELLIGENCE CARD
   ========================================================= */

function createIntelligenceCard(
    item,
    type,
    index
) {

    const card =
        document.createElement(
            "div"
        );

    card.className =
        "analysis-item intelligence-card";

    if (
        item === null ||
        typeof item !== "object"
    ) {

        card.textContent =
            String(item);

        return card;
    }

    const title =
        document.createElement(
            "div"
        );

    title.className =
        "intelligence-title";

    const primaryValue =
        getPrimaryIntelligenceValue(
            item,
            type
        );

    title.textContent =
        primaryValue ||
        (
            type === "url"
                ? "URL Result " + (index + 1)
                : "IP Result " + (index + 1)
        );

    card.appendChild(
        title
    );

    const fields =
        getDisplayFields(
            item,
            type
        );

    if (
        fields.length === 0
    ) {

        const raw =
            document.createElement(
                "pre"
            );

        raw.className =
            "intelligence-raw";

        raw.textContent =
            JSON.stringify(
                item,
                null,
                2
            );

        card.appendChild(
            raw
        );

        return card;
    }

    fields.forEach(
        function (field) {

            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "intelligence-row";

            const label =
                document.createElement(
                    "span"
                );

            label.className =
                "intelligence-label";

            label.textContent =
                formatLabel(
                    field.key
                );

            const value =
                document.createElement(
                    "span"
                );

            value.className =
                "intelligence-value";

            value.textContent =
                formatIntelligenceValue(
                    field.value
                );

            row.appendChild(
                label
            );

            row.appendChild(
                value
            );

            card.appendChild(
                row
            );
        }
    );

    return card;
}


/* =========================================================
   PRIMARY INTELLIGENCE VALUE
   ========================================================= */

function getPrimaryIntelligenceValue(
    item,
    type
) {

    const keys =
        type === "url"
            ? [
                "url",
                "URL",
                "uri",
                "link",
                "domain"
            ]
            : [
                "ip",
                "IP",
                "ipAddress",
                "ip_address",
                "address"
            ];

    return getValue(
        item,
        keys,
        null
    );
}


/* =========================================================
   DISPLAY INTELLIGENCE FIELDS
   ========================================================= */

function getDisplayFields(
    item,
    type
) {

    const preferred =
        type === "url"
            ? [
                "url",
                "domain",
                "protocol",
                "risk",
                "riskScore",
                "reputation",
                "threat",
                "threatLevel",
                "category",
                "status",
                "reason",
                "message"
            ]
            : [
                "ip",
                "country",
                "countryName",
                "region",
                "regionName",
                "city",
                "isp",
                "organization",
                "org",
                "asn",
                "latitude",
                "longitude",
                "risk",
                "riskScore",
                "reputation",
                "threat",
                "threatLevel",
                "status",
                "reason"
            ];

    const fields = [];

    preferred.forEach(
        function (key) {

            if (
                Object.prototype.hasOwnProperty.call(
                    item,
                    key
                ) &&
                item[key] !== null &&
                item[key] !== undefined &&
                item[key] !== ""
            ) {

                fields.push({
                    key: key,
                    value: item[key]
                });
            }
        }
    );

    if (
        fields.length === 0
    ) {

        Object.keys(
            item
        ).forEach(
            function (key) {

                const value =
                    item[key];

                if (
                    value === null ||
                    value === undefined ||
                    value === ""
                ) {
                    return;
                }

                if (
                    typeof value ===
                        "object"
                ) {

                    fields.push({
                        key: key,
                        value:
                            JSON.stringify(
                                value
                            )
                    });

                } else {

                    fields.push({
                        key: key,
                        value: value
                    });
                }
            }
        );
    }

    return fields.slice(
        0,
        12
    );
}


/* =========================================================
   GEOLOCATION
   ========================================================= */

function updateGeoLocation(data) {

    const geo =
        data.geoLocation ||
        data.geolocation ||
        data.geo ||
        data.ipGeolocation ||
        null;

    if (!geo) {
        return;
    }

    const ipContainer =
        document.getElementById(
            "ipAnalysis"
        );

    if (!ipContainer) {
        return;
    }

    let existingPanel =
        ipContainer.querySelector(
            ".intelligence-panel"
        );

    if (!existingPanel) {

        existingPanel =
            document.createElement(
                "div"
            );

        existingPanel.className =
            "intelligence-panel";

        ipContainer.innerHTML = "";

        ipContainer.appendChild(
            existingPanel
        );
    }

    const geoCard =
        document.createElement(
            "div"
        );

    geoCard.className =
        "analysis-item intelligence-card geo-card";

    const heading =
        document.createElement(
            "div"
        );

    heading.className =
        "intelligence-title";

    heading.textContent =
        "Geolocation Intelligence";

    geoCard.appendChild(
        heading
    );

    const geoFields = [
        "country",
        "countryName",
        "region",
        "regionName",
        "city",
        "isp",
        "organization",
        "org",
        "asn",
        "latitude",
        "longitude",
        "coordinates"
    ];

    let added = 0;

    geoFields.forEach(
        function (key) {

            if (
                Object.prototype.hasOwnProperty.call(
                    geo,
                    key
                ) &&
                geo[key] !== null &&
                geo[key] !== undefined &&
                geo[key] !== ""
            ) {

                const row =
                    document.createElement(
                        "div"
                    );

                row.className =
                    "intelligence-row";

                const label =
                    document.createElement(
                        "span"
                    );

                label.className =
                    "intelligence-label";

                label.textContent =
                    formatLabel(
                        key
                    );

                const value =
                    document.createElement(
                        "span"
                    );

                value.className =
                    "intelligence-value";

                value.textContent =
                    formatIntelligenceValue(
                        geo[key]
                    );

                row.appendChild(
                    label
                );

                row.appendChild(
                    value
                );

                geoCard.appendChild(
                    row
                );

                added++;
            }
        }
    );

    if (added === 0) {

        const raw =
            document.createElement(
                "pre"
            );

        raw.className =
            "intelligence-raw";

        raw.textContent =
            JSON.stringify(
                geo,
                null,
                2
            );

        geoCard.appendChild(
            raw
        );
    }

    existingPanel.appendChild(
        geoCard
    );
}


/* =========================================================
   THREAT GRAPH
   ========================================================= */

function updateThreatGraph(data) {

    const graphData =
        data.threatGraph ||
        data.graph ||
        data.relationshipGraph ||
        null;

    const container =
        document.getElementById(
            "threatGraphContainer"
        );

    const emptyState =
        document.getElementById(
            "graphEmptyState"
        );

    if (!container) {
        return;
    }

    if (!graphData) {

        if (emptyState) {
            emptyState.style.display =
                "flex";
        }

        return;
    }

    window.currentThreatGraph =
        graphData;

    if (emptyState) {
        emptyState.style.display =
            "none";
    }

    /*
       Use the existing renderer if one exists.
       This does not replace the application's
       graph implementation.
    */

    if (
        typeof window.renderThreatGraph ===
        "function"
    ) {

        try {

            window.renderThreatGraph(
                graphData
            );

        } catch (error) {

            console.error(
                "Threat graph rendering error:",
                error
            );
        }
    }
}


/* =========================================================
   RESET INVESTIGATION
   ========================================================= */

function resetInvestigation() {

    currentAnalysisData = null;
    currentFile = null;
    isAnalyzing = false;

    const fileInput =
        document.getElementById(
            "emailFile"
        );

    if (fileInput) {
        fileInput.value = "";
    }

    const idsToReset = [
        "threatScore",
        "verdict",
        "confidence",
        "urlCount",
        "ipCount",
        "sender",
        "recipient",
        "subject",
        "emailDate",
        "messageId",
        "replyTo",
        "spfStatus",
        "dkimStatus",
        "dmarcStatus",
        "authDetails",
        "attachmentsList",
        "indicators",
        "extractedUrls",
        "extractedIPs",
        "relayPath",
        "headerIPs",
        "emailBodyText",
        "rawHeadersText",
        "urlAnalysis",
        "ipAnalysis"
    ];

    idsToReset.forEach(
        function (id) {

            const element =
                document.getElementById(
                    id
                );

            if (!element) {
                return;
            }

            if (
                id === "attachmentsList" ||
                id === "indicators" ||
                id === "extractedUrls" ||
                id === "extractedIPs" ||
                id === "relayPath" ||
                id === "headerIPs" ||
                id === "urlAnalysis" ||
                id === "ipAnalysis"
            ) {

                element.innerHTML = "";

            } else {

                element.textContent = "—";
            }
        }
    );

    const scoreBar =
        document.getElementById(
            "scoreBar"
        );

    if (scoreBar) {
        scoreBar.style.width = "0%";
    }

    const htmlPreview =
        document.getElementById(
            "emailHtmlPreview"
        );

    if (htmlPreview) {
        htmlPreview.innerHTML = "";
    }

    const graphContainer =
        document.getElementById(
            "threatGraphContainer"
        );

    if (graphContainer) {

        const svg =
            graphContainer.querySelector(
                ".threat-graph-svg"
            );

        if (svg) {
            svg.innerHTML = "";
        }
    }

    const graphEmptyState =
        document.getElementById(
            "graphEmptyState"
        );

    if (graphEmptyState) {

        graphEmptyState.style.display =
            "flex";
    }

    showAnalysisMessage(
        "Ready for a new email analysis.",
        "info"
    );

    resetAnalysisButton();

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}


/* =========================================================
   EXPORT REPORT
   ========================================================= */

function exportReport() {

    if (!currentAnalysisData) {

        alert(
            "Please analyze an email before exporting the report."
        );

        return;
    }

    window.print();
}


/* =========================================================
   LOGOUT
   ========================================================= */

function logout() {

    sessionStorage.removeItem(
        "investigator_session"
    );

    window.location.href =
        "index.html";
}


/* =========================================================
   BUTTON STATE
   ========================================================= */

function setAnalyzeButtonState(
    analyzing
) {

    const button =
        document.getElementById(
            "analyzeButton"
        );

    if (!button) {
        return;
    }

    if (analyzing) {

        button.disabled = true;

        button.dataset.originalText =
            button.textContent;

        button.textContent =
            "Analyzing...";

    } else {

        button.disabled = false;

        button.textContent =
            button.dataset.originalText ||
            "Analyze Email";
    }
}


function resetAnalysisButton() {
    setAnalyzeButtonState(false);
}


/* =========================================================
   STATUS MESSAGE
   ========================================================= */

function showAnalysisMessage(
    message,
    type
) {

    const element =
        document.getElementById(
            "analysisMessage"
        );

    if (!element) {
        return;
    }

    element.textContent =
        message;

    element.classList.remove(
        "success",
        "error",
        "loading",
        "info"
    );

    if (type) {
        element.classList.add(
            type
        );
    }
}


/* =========================================================
   SCROLL SPY
   ========================================================= */

function setupScrollSpy() {

    const sections = [
        "dashboard",
        "emailForensics",
        "emailContent",
        "urlIntelligence",
        "geoLocation",
        "threatGraph"
    ];

    const navItems =
        document.querySelectorAll(
            ".nav-item"
        );

    if (!sections.length) {
        return;
    }

    const observer =
        new IntersectionObserver(
            function (entries) {

                entries.forEach(
                    function (entry) {

                        if (
                            !entry.isIntersecting
                        ) {
                            return;
                        }

                        const id =
                            entry.target.id;

                        activateNavigationItem(
                            id
                        );
                    }
                );

            },
            {
                threshold: 0.2,
                rootMargin:
                    "-20% 0px -60% 0px"
            }
        );

    sections.forEach(
        function (id) {

            const section =
                document.getElementById(
                    id
                );

            if (section) {
                observer.observe(
                    section
                );
            }
        }
    );
}


/* =========================================================
   SCROLL TO RESULTS
   ========================================================= */

function scrollToResults() {

    const section =
        document.getElementById(
            "emailForensics"
        );

    if (!section) {
        return;
    }

    setTimeout(
        function () {

            section.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        },
        300
    );
}


/* =========================================================
   UTILITY - SET TEXT
   ========================================================= */

function setText(
    id,
    value
) {

    const element =
        document.getElementById(
            id
        );

    if (!element) {
        return;
    }

    element.textContent =
        value === null ||
        value === undefined ||
        value === ""
            ? "—"
            : String(value);
}


/* =========================================================
   UTILITY - GET VALUE
   ========================================================= */

function getValue(
    object,
    keys,
    defaultValue
) {

    if (
        !object ||
        typeof object !== "object"
    ) {
        return defaultValue;
    }

    for (
        const key of keys
    ) {

        if (
            Object.prototype.hasOwnProperty.call(
                object,
                key
            ) &&
            object[key] !== null &&
            object[key] !== undefined
        ) {

            return object[key];
        }
    }

    return defaultValue;
}


/* =========================================================
   FORMAT SCORE
   ========================================================= */

function formatScore(
    value
) {

    const number =
        parseFloat(value);

    if (
        Number.isNaN(number)
    ) {
        return String(value);
    }

    return Math.round(
        number
    );
}


/* =========================================================
   FORMAT CONFIDENCE
   ========================================================= */

function formatConfidence(
    value
) {

    let number =
        parseFloat(value);

    if (
        Number.isNaN(number)
    ) {
        return String(value);
    }

    /*
       Support:
       0.95 -> 95
       95   -> 95
    */

    if (
        number >= 0 &&
        number <= 1
    ) {
        number *= 100;
    }

    return Math.round(
        number
    );
}


/* =========================================================
   FORMAT STATUS
   ========================================================= */

function formatStatus(
    value
) {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "NOT CONFIGURED";
    }

    if (
        typeof value === "object"
    ) {

        if (value.status) {
            return String(
                value.status
            ).toUpperCase();
        }

        if (value.result) {
            return String(
                value.result
            ).toUpperCase();
        }

        return JSON.stringify(
            value
        );
    }

    return String(
        value
    ).toUpperCase();
}


/* =========================================================
   FORMAT LABEL
   ========================================================= */

function formatLabel(
    value
) {

    return String(
        value
    )
        .replace(
            /([a-z])([A-Z])/g,
            "$1 $2"
        )
        .replace(
            /_/g,
            " "
        )
        .replace(
            /\b\w/g,
            function (character) {
                return character.toUpperCase();
            }
        );
}


/* =========================================================
   FORMAT INTELLIGENCE VALUE
   ========================================================= */

function formatIntelligenceValue(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {
        return "—";
    }

    if (
        typeof value === "object"
    ) {
        return JSON.stringify(
            value
        );
    }

    return String(
        value
    );
}


/* =========================================================
   RENDER LIST
   ========================================================= */

function renderList(
    elementId,
    items,
    emptyMessage
) {

    const container =
        document.getElementById(
            elementId
        );

    if (!container) {
        return;
    }

    container.innerHTML = "";

    if (
        items === null ||
        items === undefined ||
        (
            Array.isArray(items) &&
            items.length === 0
        )
    ) {

        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "empty-message";

        empty.textContent =
            emptyMessage;

        container.appendChild(
            empty
        );

        return;
    }

    if (!Array.isArray(items)) {
        items = [items];
    }

    items.forEach(
        function (item) {

            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "forensic-item";

            if (
                typeof item === "object" &&
                item !== null
            ) {

                row.textContent =
                    JSON.stringify(
                        item,
                        null,
                        2
                    );

            } else {

                row.textContent =
                    String(item);
            }

            container.appendChild(
                row
            );
        }
    );
}


/* =========================================================
   ESCAPE HTML
   ========================================================= */

function escapeHtml(
    value
) {

    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}


/* =========================================================
   GLOBAL FUNCTIONS
   ========================================================= */

window.handleNavClick =
    handleNavClick;

window.logout =
    logout;

window.resetInvestigation =
    resetInvestigation;

window.exportReport =
    exportReport;

window.analyzeEmail =
    analyzeEmail;

window.switchContentTab =
    switchContentTab;

window.processFileAnalysis =
    processFileAnalysis;

window.displayResults =
    displayResults;

window.updateIntelligence =
    updateIntelligence;

window.renderIntelligence =
    renderIntelligence;


/* =========================================================
   READY
   ========================================================= */

console.log(
    "Email Threat Intelligence dashboard.js ready."
);