const axios = require("axios");

/*
===========================================================
IP ANALYZER
===========================================================

Purpose:
- Validate IPv4 addresses
- Identify private/reserved IP addresses
- Query public IP geolocation information
- Return safe, JSON-friendly results
- Never stop the complete email analysis if geolocation fails

Important:
The location returned by an IP geolocation service represents
approximate network/infrastructure location. It does NOT identify
the physical location of the attacker.
===========================================================
*/


/**
 * Check whether a value is a valid IPv4 address.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isValidIPv4(ip) {
    if (typeof ip !== "string") {
        return false;
    }

    const parts = ip.trim().split(".");

    if (parts.length !== 4) {
        return false;
    }

    return parts.every(part => {
        if (!/^\d+$/.test(part)) {
            return false;
        }

        const number = Number(part);

        return number >= 0 && number <= 255;
    });
}


/**
 * Convert an IPv4 address into a numeric value.
 *
 * This helps us identify private/reserved ranges.
 *
 * @param {string} ip
 * @returns {number}
 */
function ipv4ToNumber(ip) {
    const parts = ip.split(".").map(Number);

    return (
        ((parts[0] * 256 + parts[1]) * 256 + parts[2]) *
        256 +
        parts[3]
    );
}


/**
 * Check whether an IPv4 address belongs to a private,
 * loopback, link-local, multicast, or otherwise reserved range.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateOrReservedIPv4(ip) {
    if (!isValidIPv4(ip)) {
        return true;
    }

    const number = ipv4ToNumber(ip);

    /*
    10.0.0.0/8
    */
    if (
        number >= ipv4ToNumber("10.0.0.0") &&
        number <= ipv4ToNumber("10.255.255.255")
    ) {
        return true;
    }

    /*
    100.64.0.0/10
    Carrier-grade NAT
    */
    if (
        number >= ipv4ToNumber("100.64.0.0") &&
        number <= ipv4ToNumber("100.127.255.255")
    ) {
        return true;
    }

    /*
    127.0.0.0/8
    Loopback
    */
    if (
        number >= ipv4ToNumber("127.0.0.0") &&
        number <= ipv4ToNumber("127.255.255.255")
    ) {
        return true;
    }

    /*
    169.254.0.0/16
    Link-local
    */
    if (
        number >= ipv4ToNumber("169.254.0.0") &&
        number <= ipv4ToNumber("169.254.255.255")
    ) {
        return true;
    }

    /*
    172.16.0.0/12
    Private network
    */
    if (
        number >= ipv4ToNumber("172.16.0.0") &&
        number <= ipv4ToNumber("172.31.255.255")
    ) {
        return true;
    }

    /*
    192.0.0.0/24
    IETF protocol assignments
    */
    if (
        number >= ipv4ToNumber("192.0.0.0") &&
        number <= ipv4ToNumber("192.0.0.255")
    ) {
        return true;
    }

    /*
    192.0.2.0/24
    Documentation range
    */
    if (
        number >= ipv4ToNumber("192.0.2.0") &&
        number <= ipv4ToNumber("192.0.2.255")
    ) {
        return true;
    }

    /*
    192.168.0.0/16
    Private network
    */
    if (
        number >= ipv4ToNumber("192.168.0.0") &&
        number <= ipv4ToNumber("192.168.255.255")
    ) {
        return true;
    }

    /*
    198.18.0.0/15
    Benchmark testing
    */
    if (
        number >= ipv4ToNumber("198.18.0.0") &&
        number <= ipv4ToNumber("198.19.255.255")
    ) {
        return true;
    }

    /*
    198.51.100.0/24
    Documentation range
    */
    if (
        number >= ipv4ToNumber("198.51.100.0") &&
        number <= ipv4ToNumber("198.51.100.255")
    ) {
        return true;
    }

    /*
    203.0.113.0/24
    Documentation range
    */
    if (
        number >= ipv4ToNumber("203.0.113.0") &&
        number <= ipv4ToNumber("203.0.113.255")
    ) {
        return true;
    }

    /*
    224.0.0.0/4
    Multicast
    */
    if (
        number >= ipv4ToNumber("224.0.0.0") &&
        number <= ipv4ToNumber("239.255.255.255")
    ) {
        return true;
    }

    /*
    240.0.0.0/4
    Reserved
    */
    if (
        number >= ipv4ToNumber("240.0.0.0") &&
        number <= ipv4ToNumber("255.255.255.255")
    ) {
        return true;
    }

    return false;
}


/**
 * Analyze one public IPv4 address.
 *
 * @param {string} ip
 * @returns {Promise<object>}
 */
async function analyzeSingleIP(ip) {

    const cleanIP = String(ip || "").trim();

    /*
    Invalid IP
    */
    if (!isValidIPv4(cleanIP)) {

        return {
            ip: cleanIP,
            status: "INVALID",
            type: "Invalid IPv4 address",
            message: "The extracted value is not a valid IPv4 address."
        };

    }


    /*
    Private or reserved IP
    */
    if (isPrivateOrReservedIPv4(cleanIP)) {

        return {
            ip: cleanIP,
            status: "SKIPPED",
            type: "Private / Reserved IPv4",
            message:
                "This IP belongs to a private, reserved, loopback, " +
                "documentation, multicast, or special-purpose range."
        };

    }


    /*
    Public IP
    */
    try {

        /*
        Request only the fields needed by our application.

        NOTE:
        This endpoint is HTTP-based. For a production deployment,
        we should later move to a paid HTTPS/API-key service or
        another provider with appropriate production terms.
        */

        const response = await axios.get(
            `http://ip-api.com/json/${encodeURIComponent(cleanIP)}`,
            {
                params: {
                    fields:
                        "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
                },

                timeout: 5000
            }
        );


        const data = response.data;


        /*
        API reported an error
        */
        if (!data || data.status !== "success") {

            return {
                ip: cleanIP,
                status: "UNKNOWN",
                type: "Public IPv4",
                message:
                    data?.message ||
                    "Unable to retrieve geolocation information."
            };

        }


        /*
        Successful geolocation result
        */
        return {

            ip: cleanIP,

            status: "SUCCESS",

            type: "Public IPv4",

            country:
                data.country || "Unknown",

            countryCode:
                data.countryCode || "",

            region:
                data.regionName || "Unknown",

            regionCode:
                data.region || "",

            city:
                data.city || "Unknown",

            postalCode:
                data.zip || "",

            latitude:
                typeof data.lat === "number"
                    ? data.lat
                    : null,

            longitude:
                typeof data.lon === "number"
                    ? data.lon
                    : null,

            timezone:
                data.timezone || "Unknown",

            isp:
                data.isp || "Unknown",

            organization:
                data.org || "Unknown",

            autonomousSystem:
                data.as || "Unknown",

            query:
                data.query || cleanIP,

            message:
                "Approximate infrastructure geolocation retrieved successfully."

        };

    }

    catch (error) {

        console.error(
            `IP geolocation failed for ${cleanIP}:`,
            error.message
        );


        /*
        Do NOT fail the complete email investigation.

        The email can still be analyzed even if the external
        geolocation service is unavailable.
        */

        return {

            ip: cleanIP,

            status: "ERROR",

            type: "Public IPv4",

            message:
                "Geolocation service could not be reached.",

            error:
                error.message

        };

    }
}


/**
 * Analyze a list of IP addresses.
 *
 * @param {Array<string>} ips
 * @returns {Promise<Array<object>>}
 */
async function analyzeIPs(ips = []) {

    /*
    Make sure the input is an array.
    */
    if (!Array.isArray(ips)) {
        return [];
    }


    /*
    Clean and remove duplicate IP addresses.
    */
    const uniqueIPs = [
        ...new Set(
            ips
                .map(ip => String(ip || "").trim())
                .filter(Boolean)
        )
    ];


    /*
    Analyze IPs one by one.

    We intentionally process them sequentially so that we don't
    unnecessarily send many requests to the external service.
    */

    const results = [];

    for (const ip of uniqueIPs) {

        const result =
            await analyzeSingleIP(ip);

        results.push(result);

    }


    return results;
}


/*
===========================================================
EXPORTS
===========================================================
*/

module.exports = {
    analyzeIPs,
    analyzeSingleIP,
    isValidIPv4,
    isPrivateOrReservedIPv4
};