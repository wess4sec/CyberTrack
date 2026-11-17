require("dotenv").config({
    path: require("node:path").resolve(__dirname, "..", ".env"),
    quiet: true
});

process.env.NODE_ENV = "test";
process.env.TRUST_PROXY_HOPS = "1";
process.env.JWT_SECRET = require("node:crypto")
    .randomBytes(64)
    .toString("base64url");

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { after, before, test } = require("node:test");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const app = require("../app");
const {
    connectDatabase,
    disconnectDatabase
} = require("../config/database");
const Vulnerability = require("../models/Vulnerability");
const Asset = require("../models/Asset");
const User = require("../models/User");
const Scan = require("../models/Scan");
const RemediationTask = require("../models/RemediationTask");

const EXPECTED_COLLECTIONS = [
    "assets",
    "remediation_tasks",
    "scans",
    "users",
    "vulnerabilities"
];

let testDatabaseName;
let httpServer;
let baseUrl;
let primaryVulnerability;
let testAsset;
let testUser;
let testScan;
let testTask;
let viewerUser;
let originalSnapshot;
let authCookie;

async function readOriginalDatabaseSnapshot() {
    const uri = process.env.MONGODB_URI;

    if (!uri) {
        throw new Error("MONGODB_URI is not configured in server/.env.");
    }

    const client = new mongoose.mongo.MongoClient(uri, {
        serverSelectionTimeoutMS: 10000
    });

    try {
        await client.connect();
        const database = client.db("cybertrack_db");
        const collectionNames = (await database
            .listCollections({}, { nameOnly: true })
            .toArray())
            .map(collection => collection.name)
            .sort();

        return {
            vulnerabilityCount: await database
                .collection("vulnerabilities")
                .countDocuments(),
            collectionNames
        };
    } finally {
        await client.close();
    }
}

function createTestUri(uri, databaseName) {
    const parsed = new URL(uri);
    const originalDatabaseName = decodeURIComponent(
        parsed.pathname.replace(/^\/+/, "").split("/")[0] || ""
    );

    if (
        (parsed.username || parsed.password) &&
        originalDatabaseName &&
        !parsed.searchParams.has("authSource")
    ) {
        parsed.searchParams.set("authSource", originalDatabaseName);
    }

    parsed.pathname = `/${encodeURIComponent(databaseName)}`;
    return parsed.toString();
}

function vulnerabilityPayload(overrides = {}) {
    const now = new Date("2026-01-15T12:00:00.000Z");
    return {
        cveId: `CVE-2099-${Math.floor(Math.random() * 900000 + 100000)}`,
        title: "Isolated API test vulnerability",
        description: "Test-only description.",
        severity: "HIGH",
        cvss: 8.5,
        cweIds: ["CWE-79"],
        affectedProducts: ["CyberTrack Test"],
        publishedAt: now,
        lastModifiedAt: now,
        source: "API_TEST",
        status: "ACTIVE",
        references: [],
        ...overrides
    };
}

async function callApi(path, options = {}) {
    const headers = { ...(options.headers || {}) };

    if (options.body !== undefined) {
        headers["content-type"] = "application/json";
    }
    if (authCookie && !headers.cookie) {
        headers.cookie = authCookie;
    }

    const response = await fetch(`${baseUrl}${path}`, {
        ...options,
        headers,
        body:
            options.body === undefined
                ? undefined
                : JSON.stringify(options.body)
    });
    const body = await response.json();

    return { status: response.status, body, headers: response.headers };
}

before(async () => {
    originalSnapshot = await readOriginalDatabaseSnapshot();
    assert.deepEqual(originalSnapshot.collectionNames, EXPECTED_COLLECTIONS);

    testDatabaseName = `cybertrack_api_test_${randomUUID().replace(/-/g, "")}`;
    const testUri = createTestUri(process.env.MONGODB_URI, testDatabaseName);
    await connectDatabase({
        uri: testUri,
        expectedDatabase: testDatabaseName
    });

    assert.notEqual(mongoose.connection.db.databaseName, "cybertrack_db");
    assert.deepEqual(
        await mongoose.connection.db
            .listCollections({}, { nameOnly: true })
            .toArray(),
        []
    );

    primaryVulnerability = await Vulnerability.create(
        vulnerabilityPayload({
            cveId: "CVE-2099-000001",
            title: "API fixture alpha",
            severity: "HIGH",
            cvss: 8.5
        })
    );
    await Vulnerability.create(
        vulnerabilityPayload({
            cveId: "CVE-2099-000002",
            title: "API fixture beta",
            severity: "CRITICAL",
            cvss: 9.5
        })
    );
    await Vulnerability.create(
        vulnerabilityPayload({
            cveId: "CVE-2099-000003",
            title: "API fixture gamma",
            severity: "LOW",
            cvss: 2.5
        })
    );

    testAsset = await Asset.create({
        hostname: "api-test-host",
        ipAddress: "192.0.2.10",
        assetType: "SERVER",
        operatingSystem: "Test OS",
        environment: "TEST",
        criticality: "LOW",
        tags: ["api-test"],
        owner: "Test Owner"
    });
    testUser = await User.create({
        fullName: "API Test User",
        email: "api-test@example.invalid",
        passwordHash: await bcrypt.hash("test-admin-password-2026", 12),
        role: "ADMIN",
        department: "Testing"
    });
    viewerUser = await User.create({
        fullName: "API Viewer",
        email: "api-viewer@example.invalid",
        passwordHash: await bcrypt.hash("test-viewer-password-2026", 12),
        role: "VIEWER",
        department: "Testing"
    });
    testScan = await Scan.create({
        assetId: testAsset._id,
        scannedBy: testUser._id,
        scanType: "NETWORK",
        status: "COMPLETED",
        startedAt: new Date("2026-01-16T10:00:00.000Z"),
        completedAt: new Date("2026-01-16T10:01:00.000Z"),
        results: [
            {
                vulnerabilityId: primaryVulnerability._id,
                port: 443,
                protocol: "TCP",
                status: "OPEN",
                severitySnapshot: "HIGH",
                evidence: "Test fixture only.",
                detectedAt: new Date("2026-01-16T10:00:30.000Z")
            }
        ]
    });
    testTask = await RemediationTask.create({
        vulnerabilityId: primaryVulnerability._id,
        assetId: testAsset._id,
        assignedTo: testUser._id,
        createdBy: testUser._id,
        title: "API fixture task",
        description: "Test-only remediation task.",
        priority: "HIGH",
        status: "OPEN",
        dueDate: new Date("2026-02-01T00:00:00.000Z"),
        history: [
            {
                action: "CREATED",
                changedAt: new Date("2026-01-16T10:02:00.000Z"),
                note: "Test fixture."
            }
        ]
    });

    await new Promise((resolve, reject) => {
        httpServer = app.listen(0, "127.0.0.1");
        httpServer.once("listening", resolve);
        httpServer.once("error", reject);
    });

    const address = httpServer.address();
    baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
    if (httpServer) {
        await new Promise((resolve, reject) => {
            httpServer.close(error => (error ? reject(error) : resolve()));
        });
    }

    if (
        testDatabaseName &&
        mongoose.connection.readyState === 1 &&
        mongoose.connection.db.databaseName === testDatabaseName
    ) {
        await mongoose.connection.dropDatabase();
    }

    await disconnectDatabase();

    if (originalSnapshot) {
        const finalSnapshot = await readOriginalDatabaseSnapshot();
        assert.deepEqual(finalSnapshot, originalSnapshot);
    }
});

test("Express API CRUD, query validation, aggregation and isolation", async () => {
    const health = await callApi("/api/health");
    assert.equal(health.status, 200);
    assert.equal(health.body.data.database, "connected");

    assert.equal(
        (await callApi("/api/vulnerabilities")).status,
        401
    );
    const invalidLogin = await callApi("/api/auth/login", {
        method: "POST",
        body: {
            email: "api-test@example.invalid",
            password: "wrong-password"
        }
    });
    assert.equal(invalidLogin.status, 401);

    const login = await callApi("/api/auth/login", {
        method: "POST",
        headers: { "x-forwarded-proto": "https" },
        body: {
            email: "api-test@example.invalid",
            password: "test-admin-password-2026"
        }
    });
    assert.equal(login.status, 200);
    assert.equal(login.body.data.user.role, "ADMIN");
    assert.equal(JSON.stringify(login.body).includes("passwordHash"), false);
    const cookieHeader = login.headers.get("set-cookie");
    assert.ok(cookieHeader);
    assert.match(cookieHeader, /HttpOnly/i);
    assert.match(cookieHeader, /SameSite=Strict/i);
    assert.match(cookieHeader, /Secure/i);
    authCookie = cookieHeader.split(";")[0];

    const currentUser = await callApi("/api/auth/me");
    assert.equal(currentUser.status, 200);
    assert.equal(currentUser.body.data.user.email, "api-test@example.invalid");

    const firstPage = await callApi(
        "/api/vulnerabilities?page=1&limit=1&sort=cvss&order=desc"
    );
    assert.equal(firstPage.status, 200);
    assert.equal(firstPage.body.data.length, 1);
    assert.equal(firstPage.body.pagination.total, 3);
    assert.equal(firstPage.body.pagination.pages, 3);

    const search = await callApi(
        "/api/vulnerabilities/search?q=API%20fixture%20alpha"
    );
    assert.equal(search.status, 200);
    assert.equal(search.body.pagination.total, 1);
    assert.equal(search.body.data[0].cveId, "CVE-2099-000001");

    const severity = await callApi("/api/vulnerabilities?severity=HIGH");
    assert.equal(severity.status, 200);
    assert.equal(severity.body.pagination.total, 1);

    const cvss = await callApi(
        "/api/vulnerabilities?minCvss=8&maxCvss=9"
    );
    assert.equal(cvss.status, 200);
    assert.equal(cvss.body.pagination.total, 1);

    const publicationRange = await callApi(
        "/api/vulnerabilities?publishedFrom=2026-01-15&publishedTo=2026-01-15"
    );
    assert.equal(publicationRange.status, 200);
    assert.equal(publicationRange.body.pagination.total, 3);
    assert.equal(
        (await callApi("/api/vulnerabilities?publishedFrom=2026-02-31")).status,
        400
    );
    assert.equal(
        (
            await callApi(
                "/api/vulnerabilities?publishedFrom=2026-01-16&publishedTo=2026-01-15"
            )
        ).status,
        400
    );

    const status = await callApi("/api/vulnerabilities?status=ACTIVE");
    assert.equal(status.status, 200);
    assert.equal(status.body.pagination.total, 3);

    assert.equal(
        (await callApi("/api/vulnerabilities?limit=101")).status,
        400
    );
    assert.equal(
        (await callApi("/api/vulnerabilities?sort=passwordHash")).status,
        400
    );
    assert.equal(
        (await callApi("/api/vulnerabilities/search")).status,
        400
    );
    assert.equal(
        (
            await callApi("/api/vulnerabilities", {
                method: "POST",
                body: {
                    ...vulnerabilityPayload({ cveId: "CVE-2099-000012" }),
                    unexpected: "mass assignment"
                }
            })
        ).status,
        400
    );

    const vulnerability = await callApi(
        `/api/vulnerabilities/${primaryVulnerability.id}`
    );
    assert.equal(vulnerability.status, 200);
    assert.equal(vulnerability.body.data.title, "API fixture alpha");
    const vulnerabilityRelated = await callApi(
        `/api/vulnerabilities/${primaryVulnerability.id}/related`
    );
    assert.equal(vulnerabilityRelated.status, 200);
    assert.equal(vulnerabilityRelated.body.data.assets[0].hostname, "api-test-host");
    assert.equal(vulnerabilityRelated.body.data.assets[0].findingCount, 1);
    assert.equal(vulnerabilityRelated.body.data.assets[0].remediationTaskCount, 1);
    assert.equal(vulnerabilityRelated.body.data.scans.length, 1);
    assert.equal(vulnerabilityRelated.body.data.remediationTasks.length, 1);
    assert.equal(
        (await callApi("/api/vulnerabilities/not-an-object-id")).status,
        400
    );
    assert.equal(
        (await callApi(`/api/vulnerabilities/${new mongoose.Types.ObjectId()}`))
            .status,
        404
    );

    const invalidVulnerability = await callApi("/api/vulnerabilities", {
        method: "POST",
        body: vulnerabilityPayload({
            cveId: "CVE-2099-000010",
            cvss: 11
        })
    });
    assert.equal(invalidVulnerability.status, 400);

    const createdVulnerability = await callApi("/api/vulnerabilities", {
        method: "POST",
        body: vulnerabilityPayload({ cveId: "CVE-2099-000011" })
    });
    assert.equal(createdVulnerability.status, 201);

    const updatedVulnerability = await callApi(
        `/api/vulnerabilities/${createdVulnerability.body.data._id}`,
        { method: "PUT", body: { title: "Updated isolated finding" } }
    );
    assert.equal(updatedVulnerability.status, 200);
    assert.equal(updatedVulnerability.body.data.title, "Updated isolated finding");

    const referencedDelete = await callApi(
        `/api/vulnerabilities/${primaryVulnerability.id}`,
        { method: "DELETE" }
    );
    assert.equal(referencedDelete.status, 409);

    const deletedVulnerability = await callApi(
        `/api/vulnerabilities/${createdVulnerability.body.data._id}`,
        { method: "DELETE" }
    );
    assert.equal(deletedVulnerability.status, 200);
    assert.equal(deletedVulnerability.body.data.deleted, true);

    const listedAssets = await callApi("/api/assets?limit=5");
    assert.equal(listedAssets.status, 200);
    assert.equal(listedAssets.body.pagination.total, 1);
    const assetRelated = await callApi(`/api/assets/${testAsset.id}/related`);
    assert.equal(assetRelated.status, 200);
    assert.equal(assetRelated.body.data.scans.length, 1);
    assert.equal(assetRelated.body.data.remediationTasks.length, 1);
    assert.equal(assetRelated.body.data.vulnerabilities[0].cveId, "CVE-2099-000001");
    assert.equal(assetRelated.body.data.vulnerabilities[0].findingCount, 1);
    assert.equal(assetRelated.body.data.vulnerabilities[0].remediationTaskCount, 1);
    assert.equal(
        (
            await callApi(`/api/assets/${testAsset.id}`)
        ).body.data.hostname,
        "api-test-host"
    );

    const createdAsset = await callApi("/api/assets", {
        method: "POST",
        body: {
            hostname: "api-created-host",
            ipAddress: "192.0.2.11",
            assetType: "SERVER",
            operatingSystem: "Test OS",
            environment: "TEST",
            criticality: "LOW",
            tags: [],
            owner: "Test Owner"
        }
    });
    assert.equal(createdAsset.status, 201);
    const updatedAsset = await callApi(
        `/api/assets/${createdAsset.body.data._id}`,
        { method: "PUT", body: { isActive: false } }
    );
    assert.equal(updatedAsset.status, 200);
    assert.equal(updatedAsset.body.data.isActive, false);
    assert.equal(
        (
            await callApi(`/api/assets/${createdAsset.body.data._id}`, {
                method: "DELETE"
            })
        ).status,
        200
    );
    assert.equal(
        (
            await callApi(`/api/assets/${testAsset.id}`, { method: "DELETE" })
        ).status,
        409
    );

    const users = await callApi("/api/users");
    assert.equal(users.status, 200);
    assert.equal(users.body.pagination.total, 2);
    assert.equal(JSON.stringify(users.body).includes("passwordHash"), false);
    assert.equal(
        JSON.stringify(users.body).includes("test-admin-password-2026"),
        false
    );
    const assignees = await callApi("/api/users/assignees?q=API%20Test");
    assert.equal(assignees.status, 200);
    assert.equal(assignees.body.pagination.total, 1);
    assert.equal(assignees.body.data[0].fullName, "API Test User");
    assert.equal("email" in assignees.body.data[0], false);
    assert.equal("passwordHash" in assignees.body.data[0], false);

    const createdUser = await callApi("/api/users", {
        method: "POST",
        body: {
            fullName: "Created API User",
            email: "created-api@example.invalid",
            password: "another-test-password-2026",
            role: "SECURITY_ANALYST",
            department: "Testing"
        }
    });
    assert.equal(createdUser.status, 201);
    assert.equal(JSON.stringify(createdUser.body).includes("passwordHash"), false);
    assert.equal(
        JSON.stringify(createdUser.body).includes("another-test-password-2026"),
        false
    );
    const invalidUser = await callApi("/api/users", {
        method: "POST",
        body: {
            fullName: "Invalid API User",
            email: "invalid-api@example.invalid",
            password: { secret: "must-not-be-reflected" },
            role: "SECURITY_ANALYST",
            department: "Testing"
        }
    });
    assert.equal(invalidUser.status, 400);
    assert.equal(
        JSON.stringify(invalidUser.body).includes("must-not-be-reflected"),
        false
    );
    const updatedUser = await callApi(
        `/api/users/${createdUser.body.data._id}`,
        { method: "PUT", body: { department: "Updated Testing" } }
    );
    assert.equal(updatedUser.status, 200);
    assert.equal(updatedUser.body.data.department, "Updated Testing");
    assert.equal(
        (await callApi(`/api/users/${createdUser.body.data._id}`, {
            method: "DELETE"
        })).status,
        200
    );
    assert.equal(
        (await callApi(`/api/users/${testUser.id}`, { method: "DELETE" })).status,
        409
    );

    const scans = await callApi("/api/scans?status=COMPLETED");
    assert.equal(scans.status, 200);
    assert.equal(scans.body.pagination.total, 1);
    const searchedScans = await callApi("/api/scans?q=NETWORK");
    assert.equal(searchedScans.status, 200);
    assert.equal(searchedScans.body.pagination.total, 1);
    const scan = await callApi(`/api/scans/${testScan.id}`);
    assert.equal(scan.status, 200);
    assert.equal(scan.body.data.assetId.hostname, "api-test-host");
    assert.equal(scan.body.data.scannedBy.email, "api-test@example.invalid");
    assert.equal(scan.body.data.results[0].vulnerabilityId.cveId, "CVE-2099-000001");

    const createdScan = await callApi("/api/scans", {
        method: "POST",
        body: {
            assetId: testAsset.id,
            scannedBy: testUser.id,
            scanType: "NETWORK",
            status: "COMPLETED",
            startedAt: "2026-01-17T10:00:00.000Z",
            completedAt: "2026-01-17T10:01:00.000Z",
            results: []
        }
    });
    assert.equal(createdScan.status, 201);
    const updatedScan = await callApi(
        `/api/scans/${createdScan.body.data._id}`,
        { method: "PUT", body: { status: "REVIEWED" } }
    );
    assert.equal(updatedScan.status, 200);
    assert.equal(updatedScan.body.data.status, "REVIEWED");
    assert.equal(
        (await callApi(`/api/scans/${createdScan.body.data._id}`, {
            method: "DELETE"
        })).status,
        200
    );
    assert.equal(
        (
            await callApi("/api/scans", {
                method: "POST",
                body: {
                    assetId: "invalid-id",
                    scannedBy: testUser.id,
                    scanType: "NETWORK",
                    status: "PENDING",
                    startedAt: new Date().toISOString(),
                    results: []
                }
            })
        ).status,
        400
    );

    const tasks = await callApi(
        `/api/remediation?status=OPEN&assignedTo=${testUser.id}&vulnerabilityId=${primaryVulnerability.id}`
    );
    assert.equal(tasks.status, 200);
    assert.equal(tasks.body.pagination.total, 1);
    const searchedTasks = await callApi("/api/remediation?q=API%20fixture");
    assert.equal(searchedTasks.status, 200);
    assert.equal(searchedTasks.body.pagination.total, 1);
    const task = await callApi(`/api/remediation/${testTask.id}`);
    assert.equal(task.status, 200);
    assert.equal(task.body.data.vulnerabilityId.cveId, "CVE-2099-000001");
    assert.equal(task.body.data.assignedTo.email, "api-test@example.invalid");

    const createdTask = await callApi("/api/remediation", {
        method: "POST",
        body: {
            vulnerabilityId: primaryVulnerability.id,
            assetId: testAsset.id,
            assignedTo: testUser.id,
            title: "Created API task",
            description: "Test-only task.",
            priority: "HIGH",
            status: "OPEN",
            dueDate: "2026-03-01T00:00:00.000Z"
        }
    });
    assert.equal(createdTask.status, 201);
    assert.equal(createdTask.body.data.createdBy._id, testUser.id);
    assert.deepEqual(
        createdTask.body.data.history.map(entry => entry.action),
        ["CREATED"]
    );
    assert.equal(
        (
            await callApi("/api/remediation", {
                method: "POST",
                body: {
                    vulnerabilityId: primaryVulnerability.id,
                    assetId: testAsset.id,
                    assignedTo: testUser.id,
                    createdBy: viewerUser.id,
                    title: "Forged history attempt",
                    description: "This request must be rejected.",
                    priority: "HIGH",
                    status: "OPEN",
                    dueDate: "2026-03-01T00:00:00.000Z",
                    history: []
                }
            })
        ).status,
        400
    );
    const updatedTask = await callApi(
        `/api/remediation/${createdTask.body.data._id}`,
        { method: "PUT", body: { status: "IN_PROGRESS" } }
    );
    assert.equal(updatedTask.status, 200);
    assert.equal(updatedTask.body.data.status, "IN_PROGRESS");
    assert.equal(updatedTask.body.data.completedAt, null);
    assert.deepEqual(
        updatedTask.body.data.history.map(entry => entry.action),
        ["CREATED", "STATUS_CHANGED"]
    );
    const completedTask = await callApi(
        `/api/remediation/${createdTask.body.data._id}`,
        { method: "PUT", body: { status: "COMPLETED" } }
    );
    assert.equal(completedTask.status, 200);
    assert.ok(completedTask.body.data.completedAt);
    const reopenedTask = await callApi(
        `/api/remediation/${createdTask.body.data._id}`,
        { method: "PUT", body: { status: "IN_PROGRESS" } }
    );
    assert.equal(reopenedTask.status, 200);
    assert.equal(reopenedTask.body.data.completedAt, null);
    assert.equal(reopenedTask.body.data.history.length, 4);
    assert.equal(
        (
            await callApi(`/api/remediation/${createdTask.body.data._id}`, {
                method: "PUT",
                body: { history: [] }
            })
        ).status,
        400
    );
    assert.equal(
        (await callApi(`/api/remediation/${createdTask.body.data._id}`, {
            method: "DELETE"
        })).status,
        200
    );

    for (const endpoint of [
        "/api/dashboard/overview",
        "/api/dashboard/severity",
        "/api/dashboard/vulnerability-status",
        "/api/dashboard/monthly-trends",
        "/api/dashboard/top-vulnerabilities",
        "/api/dashboard/scans",
        "/api/dashboard/top-assets",
        "/api/dashboard/frequent-cves",
        "/api/vulnerabilities/stats"
    ]) {
        const response = await callApi(endpoint);
        assert.equal(response.status, 200, endpoint);
        assert.equal(response.body.success, true, endpoint);
        assert.ok(Array.isArray(response.body.data) || typeof response.body.data === "object");
    }
    const scanSummary = await callApi("/api/dashboard/scans");
    assert.equal(scanSummary.body.data[0].status, "COMPLETED");
    assert.equal(scanSummary.body.data[0].findingCount, 1);
    const topAssets = await callApi("/api/dashboard/top-assets");
    assert.equal(topAssets.body.data[0].hostname, "api-test-host");
    assert.equal(topAssets.body.data[0].findingCount, 1);
    const frequentCves = await callApi("/api/dashboard/frequent-cves");
    assert.equal(frequentCves.body.data[0].cveId, "CVE-2099-000001");
    assert.equal(frequentCves.body.data[0].occurrenceCount, 1);

    const unknownRoute = await callApi("/api/not-a-route");
    assert.equal(unknownRoute.status, 404);
    assert.equal(unknownRoute.body.success, false);

    const viewerLogin = await callApi("/api/auth/login", {
        method: "POST",
        body: {
            email: "api-viewer@example.invalid",
            password: "test-viewer-password-2026"
        }
    });
    assert.equal(viewerLogin.status, 200);
    authCookie = viewerLogin.headers.get("set-cookie").split(";")[0];
    assert.equal((await callApi("/api/vulnerabilities")).status, 200);
    assert.equal((await callApi("/api/users")).status, 403);
    assert.equal((await callApi("/api/users/assignees")).status, 403);
    assert.equal(
        (
            await callApi("/api/vulnerabilities", {
                method: "POST",
                body: vulnerabilityPayload({ cveId: "CVE-2099-000020" })
            })
        ).status,
        403
    );

    const blockedOrigin = await callApi("/api/auth/logout", {
        method: "POST",
        headers: { origin: "https://untrusted.example" }
    });
    assert.equal(blockedOrigin.status, 403);

    const logout = await callApi("/api/auth/logout", { method: "POST" });
    assert.equal(logout.status, 200);
    authCookie = undefined;
    assert.equal((await callApi("/api/vulnerabilities")).status, 401);
});
