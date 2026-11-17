const { connectDatabase, disconnectDatabase } = require("../config/database");
const Vulnerability = require("../models/Vulnerability");

const NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const SIMULATED_SOURCE = "CYBERTRACK_SIMULATED";
const MAX_RESULTS_PER_PAGE = 2000;
const MAX_ATTEMPTS = 5;

function getSeverity(metric, score) {
    const rawSeverity = String(
        metric?.cvssData?.baseSeverity || metric?.baseSeverity || ""
    ).toUpperCase();
    if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(rawSeverity)) {
        return rawSeverity;
    }
    if (score >= 9) return "CRITICAL";
    if (score >= 7) return "HIGH";
    if (score >= 4) return "MEDIUM";
    return "LOW";
}

function collectCpeCriteria(value, criteria) {
    if (!value || typeof value !== "object") return;
    for (const match of value.cpeMatch || []) {
        if (typeof match.criteria === "string") criteria.add(match.criteria);
    }
    for (const child of value.nodes || value.children || []) {
        collectCpeCriteria(child, criteria);
    }
}

function mapNvdVulnerability(entry) {
    const cve = entry?.cve;
    if (!cve || typeof cve.id !== "string" || !/^CVE-\d{4}-\d{4,}$/.test(cve.id)) {
        return null;
    }

    const metric = [
        ...(cve.metrics?.cvssMetricV40 || []),
        ...(cve.metrics?.cvssMetricV31 || []),
        ...(cve.metrics?.cvssMetricV30 || []),
        ...(cve.metrics?.cvssMetricV2 || [])
    ][0];
    const score = Number(metric?.cvssData?.baseScore);
    const publishedAt = new Date(cve.published);
    const lastModifiedAt = new Date(cve.lastModified);
    const description = (cve.descriptions || []).find(item => item.lang === "en")?.value;

    if (
        !Number.isFinite(score) ||
        score < 0 ||
        score > 10 ||
        Number.isNaN(publishedAt.getTime()) ||
        Number.isNaN(lastModifiedAt.getTime()) ||
        typeof description !== "string" ||
        !description.trim()
    ) {
        return null;
    }

    const cweIds = new Set();
    for (const weakness of cve.weaknesses || []) {
        for (const item of weakness.description || []) {
            if (/^CWE-\d+$/.test(item.value || "")) cweIds.add(item.value);
        }
    }

    const affectedProducts = new Set();
    for (const configuration of cve.configurations || []) {
        collectCpeCriteria(configuration, affectedProducts);
    }

    const references = new Set(
        (cve.references || [])
            .map(reference => reference.url)
            .filter(url => typeof url === "string" && /^https?:\/\//i.test(url))
    );

    return {
        cveId: cve.id,
        title: cve.id,
        description: description.trim(),
        severity: getSeverity(metric, score),
        cvss: score,
        cweIds: [...cweIds],
        affectedProducts: [...affectedProducts],
        publishedAt,
        lastModifiedAt,
        source: "NVD",
        references: [...references]
    };
}

function retryDelay(response, attempt) {
    const retryAfter = Number(response?.headers?.get("retry-after"));
    if (Number.isFinite(retryAfter) && retryAfter >= 0) {
        return Math.min(retryAfter * 1000, 120000);
    }
    return Math.min(1000 * (2 ** attempt), 30000);
}

async function fetchNvdPage({ startIndex, resultsPerPage, apiKey, fetchImpl, sleepImpl }) {
    const url = new URL(NVD_ENDPOINT);
    url.searchParams.set("startIndex", String(startIndex));
    url.searchParams.set("resultsPerPage", String(resultsPerPage));

    let lastError;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
        let response;
        try {
            response = await fetchImpl(url, {
                headers: apiKey ? { apiKey } : {},
                signal: AbortSignal.timeout(30000)
            });
        } catch (error) {
            lastError = error;
            if (attempt === MAX_ATTEMPTS - 1) break;
            await sleepImpl(Math.min(1000 * (2 ** attempt), 30000));
            continue;
        }

        if (response.ok) return response.json();

        const status = response.status;
        if (status !== 429 && status < 500) {
            throw new Error(`NVD API returned HTTP ${status}.`);
        }
        lastError = new Error(`NVD API returned HTTP ${status}.`);
        if (attempt < MAX_ATTEMPTS - 1) {
            await sleepImpl(retryDelay(response, attempt));
        }
    }

    throw new Error(`NVD API request failed after ${MAX_ATTEMPTS} attempts: ${lastError?.message || "network error"}`);
}

async function saveNvdPage(Model, entries) {
    const mapped = new Map();
    let invalidSkipped = 0;
    for (const entry of entries) {
        const vulnerability = mapNvdVulnerability(entry);
        if (!vulnerability) {
            invalidSkipped += 1;
            continue;
        }
        if (mapped.has(vulnerability.cveId)) invalidSkipped += 1;
        mapped.set(vulnerability.cveId, vulnerability);
    }

    if (mapped.size === 0) {
        return { inserted: 0, updated: 0, syntheticSkipped: 0, invalidSkipped };
    }

    const cveIds = [...mapped.keys()];
    const existing = await Model.find({ cveId: { $in: cveIds } })
        .select("cveId source")
        .lean()
        .exec();
    const existingById = new Map(existing.map(item => [item.cveId, item]));
    const operations = [];
    let syntheticSkipped = 0;

    for (const [cveId, vulnerability] of mapped) {
        const current = existingById.get(cveId);
        if (current?.source === SIMULATED_SOURCE) {
            syntheticSkipped += 1;
            continue;
        }

        const filter = current
            ? { _id: current._id }
            : { cveId, source: { $ne: SIMULATED_SOURCE } };
        operations.push({
            updateOne: {
                filter,
                update: {
                    $set: vulnerability,
                    $setOnInsert: { status: "ACTIVE" }
                },
                upsert: true
            }
        });
    }

    if (operations.length === 0) {
        return { inserted: 0, updated: 0, syntheticSkipped, invalidSkipped };
    }

    const result = await Model.bulkWrite(operations, { ordered: false });
    return {
        inserted: result.upsertedCount,
        updated: result.matchedCount,
        syntheticSkipped,
        invalidSkipped
    };
}

async function importNvd({
    Model = Vulnerability,
    apiKey = process.env.NVD_API_KEY,
    fetchImpl = globalThis.fetch,
    sleepImpl = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
    resultsPerPage = MAX_RESULTS_PER_PAGE
} = {}) {
    if (!Number.isInteger(resultsPerPage) || resultsPerPage < 1 || resultsPerPage > MAX_RESULTS_PER_PAGE) {
        throw new Error(`resultsPerPage must be between 1 and ${MAX_RESULTS_PER_PAGE}.`);
    }
    if (typeof fetchImpl !== "function") {
        throw new Error("A Fetch-compatible implementation is required.");
    }

    const totals = {
        fetched: 0,
        inserted: 0,
        updated: 0,
        syntheticSkipped: 0,
        invalidSkipped: 0,
        totalResults: 0
    };
    let startIndex = 0;

    while (startIndex === 0 || startIndex < totals.totalResults) {
        const page = await fetchNvdPage({
            startIndex,
            resultsPerPage,
            apiKey,
            fetchImpl,
            sleepImpl
        });

        if (
            !Number.isSafeInteger(page.totalResults) ||
            page.totalResults < 0 ||
            !Array.isArray(page.vulnerabilities)
        ) {
            throw new Error("NVD API returned an invalid pagination response.");
        }
        if (startIndex === 0) totals.totalResults = page.totalResults;
        if (page.vulnerabilities.length === 0) {
            if (startIndex < totals.totalResults) {
                throw new Error("NVD API returned an empty page before the reported result total.");
            }
            break;
        }

        const saved = await saveNvdPage(Model, page.vulnerabilities);
        totals.fetched += page.vulnerabilities.length;
        totals.inserted += saved.inserted;
        totals.updated += saved.updated;
        totals.syntheticSkipped += saved.syntheticSkipped;
        totals.invalidSkipped += saved.invalidSkipped;
        startIndex += page.vulnerabilities.length;

        if (startIndex < totals.totalResults) {
            await sleepImpl(apiKey ? 650 : 6500);
        }
    }

    return totals;
}

async function main() {
    await connectDatabase();
    try {
        const result = await importNvd();
        console.log("NVD import completed.");
        console.log(JSON.stringify(result, null, 2));
    } finally {
        await disconnectDatabase();
    }
}

if (require.main === module) {
    main().catch(error => {
        console.error("NVD import failed:", error.message);
        process.exitCode = 1;
    });
}

module.exports = {
    importNvd,
    mapNvdVulnerability,
    saveNvdPage
};
