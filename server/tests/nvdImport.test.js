const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
    importNvd,
    mapNvdVulnerability,
    saveNvdPage
} = require("../scripts/importNvd");

function nvdEntry(id, overrides = {}) {
    return {
        cve: {
            id,
            descriptions: [{ lang: "en", value: "A test vulnerability description." }],
            metrics: {
                cvssMetricV31: [{
                    cvssData: { baseScore: 8.1, baseSeverity: "HIGH" }
                }]
            },
            weaknesses: [{
                description: [{ lang: "en", value: "CWE-79" }]
            }],
            configurations: [{
                nodes: [{
                    cpeMatch: [{
                        criteria: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                    }]
                }]
            }],
            published: "2025-01-01T00:00:00.000Z",
            lastModified: "2025-01-02T00:00:00.000Z",
            references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2099-000001" }],
            ...overrides
        }
    };
}

function createModel(existingRecords = []) {
    const calls = [];
    return {
        calls,
        find() {
            return {
                select() {
                    return {
                        lean() {
                            return {
                                exec: async () => existingRecords
                            };
                        }
                    };
                }
            };
        },
        async bulkWrite(operations) {
            calls.push(...operations);
            return {
                matchedCount: operations.filter(operation => operation.updateOne.filter._id).length,
                upsertedCount: operations.filter(operation => operation.updateOne.upsert).length -
                    operations.filter(operation => operation.updateOne.filter._id).length
            };
        }
    };
}

test("maps official NVD CVE fields into the CyberTrack vulnerability shape", () => {
    const mapped = mapNvdVulnerability(nvdEntry("CVE-2099-000001"));
    assert.equal(mapped.source, "NVD");
    assert.equal(mapped.severity, "HIGH");
    assert.equal(mapped.cvss, 8.1);
    assert.deepEqual(mapped.cweIds, ["CWE-79"]);
    assert.deepEqual(mapped.affectedProducts, [
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    ]);
    assert.equal(mapped.references[0], "https://nvd.nist.gov/vuln/detail/CVE-2099-000001");
    assert.equal(mapNvdVulnerability(nvdEntry("not-a-cve")), null);
});

test("paginates NVD responses and sends an optional API key", async () => {
    const model = createModel();
    const requests = [];
    const result = await importNvd({
        Model: model,
        apiKey: "test-key",
        resultsPerPage: 1,
        sleepImpl: async () => {},
        fetchImpl: async (url, options) => {
            requests.push({ url: new URL(url), options });
            const startIndex = Number(new URL(url).searchParams.get("startIndex"));
            const entry = nvdEntry(`CVE-2099-${String(startIndex + 1).padStart(6, "0")}`);
            return {
                ok: true,
                json: async () => ({
                    totalResults: 2,
                    vulnerabilities: [entry]
                })
            };
        }
    });

    assert.equal(result.fetched, 2);
    assert.equal(result.inserted, 2);
    assert.equal(requests.length, 2);
    assert.deepEqual(requests.map(request => request.url.searchParams.get("startIndex")), ["0", "1"]);
    assert.equal(requests[0].options.headers.apiKey, "test-key");
});

test("updates real records but never overwrites synthetic demonstration records", async () => {
    const model = createModel([
        { _id: "synthetic-id", cveId: "CVE-2099-000001", source: "CYBERTRACK_SIMULATED" },
        { _id: "real-id", cveId: "CVE-2099-000002", source: "NVD" }
    ]);
    const result = await saveNvdPage(model, [
        nvdEntry("CVE-2099-000001"),
        nvdEntry("CVE-2099-000002"),
        nvdEntry("CVE-2099-000003")
    ]);

    assert.equal(result.syntheticSkipped, 1);
    assert.equal(result.updated, 1);
    assert.equal(result.inserted, 1);
    assert.equal(model.calls.length, 2);
    assert.equal(model.calls[0].updateOne.filter._id, "real-id");
    assert.deepEqual(model.calls[1].updateOne.filter, {
        cveId: "CVE-2099-000003",
        source: { $ne: "CYBERTRACK_SIMULATED" }
    });
    assert.equal("status" in model.calls[0].updateOne.update.$set, false);
    assert.equal(model.calls[0].updateOne.update.$setOnInsert.status, "ACTIVE");
});

test("retries rate-limited NVD requests using Retry-After", async () => {
    const delays = [];
    let attempts = 0;
    const model = createModel();
    const result = await importNvd({
        Model: model,
        resultsPerPage: 1,
        sleepImpl: async milliseconds => delays.push(milliseconds),
        fetchImpl: async () => {
            attempts += 1;
            if (attempts === 1) {
                return {
                    ok: false,
                    status: 429,
                    headers: { get: () => "2" }
                };
            }
            return {
                ok: true,
                json: async () => ({ totalResults: 0, vulnerabilities: [] })
            };
        }
    });

    assert.equal(attempts, 2);
    assert.deepEqual(delays, [2000]);
    assert.equal(result.fetched, 0);
});
