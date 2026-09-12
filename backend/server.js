const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");

const { parseEmail } =
    require("./emailParser");

const { analyzeThreat } =
    require("./threatAnalyzer");

const { analyzeIPs } =
    require("./ipAnalyzer");


/*
===========================================================
EMAIL THREAT DETECTION SERVER
===========================================================

This server:

1. Serves the frontend
2. Accepts .eml email files
3. Parses email contents
4. Extracts URLs and IP addresses
5. Performs threat analysis
6. Performs IP infrastructure geolocation
7. Sends all analysis results to the dashboard

===========================================================
*/


const app = express();

const PORT = 3000;


/*
===========================================================
MIDDLEWARE
===========================================================
*/


app.use(
    cors()
);


app.use(
    express.json()
);


/*
Serve the frontend folder.
*/
app.use(
    express.static(
        path.join(
            __dirname,
            "../frontend"
        )
    )
);


/*
===========================================================
FILE UPLOAD CONFIGURATION
===========================================================
*/


/*
Store uploaded emails in memory.

We do not permanently save the uploaded email at this stage.
*/
const storage =
    multer.memoryStorage();


const upload =
    multer({

        storage: storage,

        limits: {

            /*
            Maximum email size: 10 MB
            */
            fileSize:
                10 * 1024 * 1024

        },

        fileFilter:
            function (
                req,
                file,
                cb
            ) {

                const extension =
                    path.extname(
                        file.originalname
                    ).toLowerCase();


                /*
                Only .eml files are allowed.
                */

                if (
                    extension !== ".eml"
                ) {

                    return cb(
                        new Error(
                            "Only .eml files are allowed."
                        )
                    );

                }


                cb(
                    null,
                    true
                );

            }

    });


/*
===========================================================
HOME PAGE
===========================================================
*/


app.get(
    "/",
    (req, res) => {

        res.sendFile(

            path.join(
                __dirname,
                "../frontend/index.html"
            )

        );

    }
);


/*
===========================================================
BACKEND TEST ROUTE
===========================================================
*/


app.get(
    "/api/test",
    (req, res) => {

        res.json({

            success: true,

            message:
                "Email Threat Detection Backend is working."

        });

    }
);


/*
===========================================================
EMAIL ANALYSIS API
===========================================================
*/


app.post(

    "/api/analyze",

    upload.single("email"),

    async (
        req,
        res
    ) => {

        try {

            /*
            ------------------------------------------------
            STEP 1 — CHECK FILE
            ------------------------------------------------
            */

            if (!req.file) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please upload an .eml file."

                });

            }


            console.log(
                "-------------------------------------"
            );

            console.log(
                "Email received:",
                req.file.originalname
            );


            /*
            ------------------------------------------------
            STEP 2 — PARSE EMAIL
            ------------------------------------------------
            */

            const email =
                await parseEmail(
                    req.file.buffer
                );


            console.log(
                "Email parsed successfully."
            );


            /*
            ------------------------------------------------
            STEP 3 — THREAT ANALYSIS
            ------------------------------------------------
            */

            const threat =
                analyzeThreat(
                    email
                );


            console.log(
                "Threat analysis completed."
            );


            console.log(
                "Threat Score:",
                threat.score
            );


            console.log(
                "Verdict:",
                threat.verdict
            );


            console.log(
                "Confidence:",
                threat.confidence + "%"
            );


            /*
            ------------------------------------------------
            STEP 4 — COLLECT IP ADDRESSES
            ------------------------------------------------

            We combine:

            - IPs found in the email body
            - IPs found in email headers

            This is important because malicious infrastructure
            is commonly discovered in Received headers.
            ------------------------------------------------
            */


            const bodyIPs =
                email.ips || [];


            const headerIPs =
                email.headerIPs || [];


            const combinedIPs = [
                ...new Set(
                    [
                        ...bodyIPs,
                        ...headerIPs
                    ]
                )
            ];


            console.log(
                "Body IPs:",
                bodyIPs
            );


            console.log(
                "Header IPs:",
                headerIPs
            );


            console.log(
                "Total unique IPs:",
                combinedIPs.length
            );


            /*
            ------------------------------------------------
            STEP 5 — IP INFRASTRUCTURE ANALYSIS
            ------------------------------------------------

            The IP analyzer:

            - validates IPv4 addresses
            - skips private/reserved addresses
            - queries public IP geolocation
            - returns approximate infrastructure location
            ------------------------------------------------
            */


            let ipAnalysis = [];


            try {

                ipAnalysis =
                    await analyzeIPs(
                        combinedIPs
                    );


                console.log(
                    "IP infrastructure analysis completed."
                );


                console.log(
                    "IPs analyzed:",
                    ipAnalysis.length
                );

            }

            catch (ipError) {

                /*
                IP analysis should NEVER cause the entire
                email investigation to fail.
                */

                console.error(
                    "IP analysis error:",
                    ipError.message
                );


                ipAnalysis = [];

            }


            /*
            ------------------------------------------------
            STEP 6 — LOG URL ANALYSIS
            ------------------------------------------------
            */

            console.log(
                "URLs analyzed:",
                threat.urlAnalysis
                    ? threat.urlAnalysis.length
                    : 0
            );


            /*
            ------------------------------------------------
            STEP 7 — BUILD RESPONSE
            ------------------------------------------------
            */

            const result = {

                success: true,


                /*
                Uploaded file
                */

                fileName:
                    req.file.originalname,


                /*
                --------------------------------------------
                EMAIL INFORMATION
                --------------------------------------------
                */

                email: {

                    sender:
                        email.sender,

                    recipient:
                        email.recipient,

                    subject:
                        email.subject,

                    date:
                        email.date,

                    messageId:
                        email.messageId,

                    replyTo:
                        email.replyTo

                },


                /*
                --------------------------------------------
                EMAIL HEADERS
                --------------------------------------------
                */

                headers:
                    email.headers || {},


                /*
                --------------------------------------------
                EMAIL BODY
                --------------------------------------------
                */

                body:
                    email.body || "",


                /*
                --------------------------------------------
                EXTRACTED URLS
                --------------------------------------------
                */

                urls:
                    email.urls || [],


                /*
                --------------------------------------------
                URL INTELLIGENCE
                --------------------------------------------
                */

                urlAnalysis:
                    threat.urlAnalysis || [],


                /*
                --------------------------------------------
                BODY IP ADDRESSES
                --------------------------------------------
                */

                ips:
                    bodyIPs,


                /*
                --------------------------------------------
                EMAIL RELAY PATH
                --------------------------------------------
                */

                received:
                    email.received || [],


                /*
                --------------------------------------------
                HEADER IP ADDRESSES
                --------------------------------------------
                */

                headerIPs:
                    headerIPs,


                /*
                --------------------------------------------
                COMBINED IP ADDRESSES
                --------------------------------------------
                */

                allIPs:
                    combinedIPs,


                /*
                --------------------------------------------
                IP INFRASTRUCTURE GEOLOCATION
                --------------------------------------------
                */

                ipAnalysis:
                    ipAnalysis,


                /*
                --------------------------------------------
                THREAT INDICATORS
                --------------------------------------------
                */

                indicators:
                    threat.indicators || [],


                /*
                --------------------------------------------
                THREAT FINDINGS
                --------------------------------------------
                */

                findings:
                    threat.findings || [],


                /*
                --------------------------------------------
                FINAL THREAT SCORE
                --------------------------------------------
                */

                threatScore:
                    threat.score,


                /*
                --------------------------------------------
                VERDICT
                --------------------------------------------
                */

                verdict:
                    threat.verdict,


                /*
                --------------------------------------------
                CONFIDENCE
                --------------------------------------------
                */

                confidence:
                    threat.confidence,


                /*
                --------------------------------------------
                HTML BODY
                --------------------------------------------
                */

                htmlBody:
                    email.htmlBody || "",


                /*
                --------------------------------------------
                ATTACHMENTS & ANALYSIS
                --------------------------------------------
                */

                attachments:
                    email.attachments || [],

                attachmentsAnalysis:
                    threat.attachmentsAnalysis || [],


                /*
                --------------------------------------------
                AUTHENTICATION STATUS (SPF, DKIM, DMARC)
                --------------------------------------------
                */

                authentication:
                    threat.authentication ||
                    email.authentication ||
                    {
                        spf: "NOT CONFIGURED",
                        dkim: "NOT CONFIGURED",
                        dmarc: "NOT CONFIGURED",
                        details: []
                    },


                /*
                --------------------------------------------
                LINK SPOOFING MISMATCHES
                --------------------------------------------
                */

                linkMismatches:
                    email.linkMismatches || []

            };


            /*
            ------------------------------------------------
            STEP 8 — SEND RESPONSE
            ------------------------------------------------
            */

            console.log(
                "Sending analysis response..."
            );


            res.status(200).json(
                result
            );


            console.log(
                "Response sent successfully."
            );


            console.log(
                "-------------------------------------"
            );

        }


        catch (error) {

            console.error(
                "====================================="
            );


            console.error(
                "ANALYSIS ERROR"
            );


            console.error(
                error
            );


            console.error(
                "====================================="
            );


            /*
            Prevent another response if headers
            have already been sent.
            */

            if (
                res.headersSent
            ) {

                return;

            }


            res.status(500).json({

                success: false,

                message:
                    "Failed to analyze email.",

                error:
                    error.message

            });

        }

    }

);


/*
===========================================================
GLOBAL ERROR HANDLER
===========================================================
*/


app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Server error:",
            error
        );


        /*
        Multer-specific errors
        */

        if (
            error instanceof multer.MulterError
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "File upload error.",

                error:
                    error.message

            });

        }


        /*
        General server errors
        */

        res.status(500).json({

            success: false,

            message:
                error.message ||
                "Internal server error."

        });

    }
);


/*
===========================================================
START SERVER
===========================================================
*/


app.listen(

    PORT,

    () => {

        console.log(
            "====================================="
        );


        console.log(
            "Email Threat Detection Platform"
        );


        console.log(
            "====================================="
        );


        console.log(
            `Server running at http://localhost:${PORT}`
        );


        console.log(
            "====================================="
        );

    }

);