const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const multer = require("multer");
const path = require("path");

const { parseEmail } = require("./emailParser");
const { analyzeThreat } = require("./threatAnalyzer");
const { analyzeIPs } = require("./ipAnalyzer");
const { validateEmailAuthentication, extractDomain } = require("./authValidator");
const { detectPhishingML } = require("./mlDetector");
const { auditDomain } = require("./domainAnalyzer");
const { generateForensicReport } = require("./reportGenerator");

/*
===========================================================
PRODUCTION SOC EMAIL THREAT DETECTION & INTELLIGENCE SERVER
===========================================================
*/

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = 3000;

// Socket.io connection logging
io.on("connection", (socket) => {
    console.log(`[SOC WebSocket] Analyst connected: ${socket.id}`);

    socket.on("disconnect", () => {
        console.log(`[SOC WebSocket] Analyst disconnected: ${socket.id}`);
    });
});

/*
===========================================================
MIDDLEWARE
===========================================================
*/

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));

// Serve frontend static assets
app.use(express.static(path.join(__dirname, "../frontend")));

/*
===========================================================
FILE UPLOAD CONFIGURATION (In-Memory Buffer)
===========================================================
*/

const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 15 * 1024 * 1024 // 15 MB
    },
    fileFilter: function (req, file, cb) {
        const extension = path.extname(file.originalname).toLowerCase();
        if (extension !== ".eml") {
            return cb(new Error("Only .eml files are allowed."));
        }
        cb(null, true);
    }
});

/*
===========================================================
ROUTES
===========================================================
*/

// Home page (Login)
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

// Dashboard page
app.get("/dashboard.html", (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend/dashboard.html"));
});

// Health check route
app.get("/api/test", (req, res) => {
    res.json({
        success: true,
        status: "ONLINE",
        message: "Email Threat Detection SOC Backend is operational.",
        timestamp: new Date().toISOString()
    });
});

/*
===========================================================
EMAIL FORENSIC ANALYSIS PIPELINE (POST /api/analyze)
===========================================================
*/

app.post("/api/analyze", upload.single("email"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: "Please upload an .eml file."
            });
        }

        console.log("=========================================");
        console.log("[INVESTIGATION START] Ingested:", req.file.originalname);
        console.log("Size:", req.file.size, "bytes");

        // 1. PARSE EMAIL & EXTRACT RFC HEADERS / HASHES / RELAY TRACE
        const email = await parseEmail(req.file.buffer);
        console.log("Email parsed successfully. Subject:", email.subject);
        console.log("SHA-256:", email.hashes?.sha256);

        // 2. IDENTIFY CONNECTING MTA IP & EXTRACT SENDER DOMAIN
        const senderDomain = extractDomain(email.sender);
        const connectingIP = email.relayTrace?.[0]?.ip || email.headerIPs?.[0] || null;

        console.log("Sender Domain:", senderDomain);
        console.log("Connecting MTA IP:", connectingIP);

        // 3. COMBINE ALL INFRASTRUCTURE IP ADDRESSES
        const allIPs = [
            ...new Set([
                ...(email.ips || []),
                ...(email.headerIPs || []),
                ...(email.relayTrace?.map(h => h.ip).filter(Boolean) || [])
            ])
        ];
        console.log("Total unique infrastructure IPs to audit:", allIPs.length);

        // 4. PARALLEL DEEP INTELLIGENCE AUDIT
        console.log("Executing parallel intelligence engines (Auth, ML, Domain, IP)...");
        const [authValidation, mlAnalysis, domainAnalysis, ipAnalysis] = await Promise.all([
            validateEmailAuthentication(senderDomain, connectingIP, email.headers).catch(err => {
                console.error("Auth validation error:", err.message);
                return {
                    fromDomain: senderDomain,
                    spf: "NOT CONFIGURED",
                    dkim: "NOT CONFIGURED",
                    dmarc: "NOT CONFIGURED",
                    details: ["Authentication lookup failed: " + err.message]
                };
            }),

            detectPhishingML(email.body, email.subject, email.headers).catch(err => {
                console.error("ML phishing detection error:", err.message);
                return {
                    verdict: "CLEAN",
                    confidence: 0.70,
                    score: 0,
                    model: "Fallback Classifier",
                    provider: "On-Premises Engine",
                    features: [],
                    explanation: "ML analysis encountered an error."
                };
            }),

            auditDomain(senderDomain).catch(err => {
                console.error("Domain audit error:", err.message);
                return {
                    domain: senderDomain,
                    hasMx: true,
                    hasA: true,
                    domainRiskScore: 0,
                    findings: []
                };
            }),

            analyzeIPs(allIPs).catch(err => {
                console.error("IP analysis error:", err.message);
                return [];
            })
        ]);

        console.log("Intelligence engines completed.");
        console.log(`- SPF: ${authValidation.spf}, DKIM: ${authValidation.dkim}, DMARC: ${authValidation.dmarc}`);
        console.log(`- ML Verdict: ${mlAnalysis.verdict} (${mlAnalysis.score}/100, ${(mlAnalysis.confidence * 100).toFixed(0)}%)`);
        console.log(`- Domain Risk: ${domainAnalysis.domainRiskScore}/100 (Has MX: ${domainAnalysis.hasMx})`);
        console.log(`- IPs Analyzed: ${ipAnalysis.length}`);

        // 5. COMPOSITE MULTI-SIGNAL THREAT ANALYSIS
        const threat = analyzeThreat(email, {
            authValidation,
            mlAnalysis,
            domainAnalysis,
            ipAnalysis
        });

        console.log("-----------------------------------------");
        console.log("COMPOSITE THREAT ASSESSMENT:");
        console.log("Final Threat Score:", threat.score);
        console.log("Final Verdict:", threat.verdict);
        console.log("Confidence:", threat.confidence + "%");
        console.log("Findings Flagged:", threat.findings.length);

        // 6. ASSEMBLE COMPREHENSIVE RESULT DATASET
        const result = {
            success: true,
            fileName: req.file.originalname,
            hashes: email.hashes,

            email: {
                sender: email.sender,
                recipient: email.recipient,
                subject: email.subject,
                date: email.date,
                messageId: email.messageId,
                replyTo: email.replyTo
            },

            headers: email.headers || {},
            body: email.body || "",
            htmlBody: email.htmlBody || "",

            urls: email.urls || [],
            urlAnalysis: threat.urlAnalysis || [],

            ips: email.ips || [],
            headerIPs: email.headerIPs || [],
            allIPs: allIPs,
            ipAnalysis: ipAnalysis,

            received: email.received || [],
            relayTrace: email.relayTrace || [],

            attachments: email.attachments || [],
            attachmentsAnalysis: threat.attachmentsAnalysis || [],

            authentication: authValidation,
            mlAnalysis: mlAnalysis,
            domainAnalysis: domainAnalysis,
            linkMismatches: email.linkMismatches || [],

            findings: threat.findings || [],
            indicators: threat.indicators || threat.findings || [],
            threatScore: threat.score,
            verdict: threat.verdict,
            confidence: threat.confidence
        };

        // 7. REAL-TIME THREAT WEBSOCKET BROADCAST
        if (threat.score >= 40 || threat.verdict === "HIGH RISK" || threat.verdict === "MEDIUM RISK") {
            io.emit("threat_alert", {
                severity: threat.verdict === "HIGH RISK" ? "CRITICAL" : "WARNING",
                score: threat.score,
                verdict: threat.verdict,
                fileName: req.file.originalname,
                sender: email.sender,
                subject: email.subject,
                mlVerdict: mlAnalysis.verdict,
                timestamp: new Date().toISOString()
            });
            console.log("[SOC WebSocket] Broadcasted real-time threat alert.");
        }

        console.log("[INVESTIGATION COMPLETE] Sending JSON response.");
        console.log("=========================================");

        res.status(200).json(result);

    } catch (error) {
        console.error("=========================================");
        console.error("ANALYSIS FAILED FATALLY:", error);
        console.error("=========================================");

        if (res.headersSent) return;

        res.status(500).json({
            success: false,
            message: "Failed to analyze email evidence.",
            error: error.message
        });
    }
});

/*
===========================================================
COURT-ADMISSIBLE FORENSIC PDF REPORT (POST /api/report)
===========================================================
*/

app.post("/api/report", async (req, res) => {
    try {
        const analysisData = req.body;

        if (!analysisData || (!analysisData.email && !analysisData.fileName)) {
            return res.status(400).json({
                success: false,
                message: "Invalid or empty analysis data provided for PDF generation."
            });
        }

        const safeFilename = (analysisData.fileName || "Email_Evidence").replace(/[^a-zA-Z0-9_-]/g, "_");
        const pdfName = `SOC_Forensic_Report_${safeFilename}_${Date.now()}.pdf`;

        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="${pdfName}"`);

        console.log(`[PDF Generator] Generating court-admissible report for: ${safeFilename}`);
        generateForensicReport(analysisData, res);

    } catch (error) {
        console.error("PDF generation failed:", error);
        if (res.headersSent) return;
        res.status(500).json({
            success: false,
            message: "Failed to generate forensic PDF report.",
            error: error.message
        });
    }
});

/*
===========================================================
GLOBAL ERROR HANDLER
===========================================================
*/

app.use((error, req, res, next) => {
    console.error("Unhandled server error:", error);

    if (error instanceof multer.MulterError) {
        return res.status(400).json({
            success: false,
            message: "File upload error: " + error.message
        });
    }

    res.status(500).json({
        success: false,
        message: error.message || "Internal server error."
    });
});

/*
===========================================================
SERVER INITIALIZATION
===========================================================
*/

server.listen(PORT, () => {
    console.log("=================================================");
    console.log("🛡️  EMAIL THREAT INTELLIGENCE SOC PLATFORM ACTIVE");
    console.log("=================================================");
    console.log(`Server listening at: http://localhost:${PORT}`);
    console.log(`WebSocket Engine: Socket.IO mounted on port ${PORT}`);
    console.log(`Ready for forensic investigations.`);
    console.log("=================================================");
});