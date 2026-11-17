
require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");
const { faker } = require("@faker-js/faker");

const BATCH_SIZE = 1000;
const TOTAL_DOCUMENTS = 10000;

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const CWE_POOL = [
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-78",
    "CWE-22",
    "CWE-287",
    "CWE-125",
    "CWE-200",
    "CWE-352",
    "CWE-434",
    "CWE-476",
    "CWE-502"
];

const PRODUCTS = [
    "Apache HTTP Server",
    "Nginx",
    "OpenSSH",
    "Microsoft Windows Server",
    "Ubuntu Server",
    "MySQL",
    "MongoDB",
    "PostgreSQL",
    "Docker Engine",
    "Node.js",
    "WordPress",
    "Jenkins",
    "Redis",
    "Kubernetes"
];

function generateSeverity() {
    const value = faker.number.int({ min: 1, max: 100 });

    if (value <= 10) return "CRITICAL";
    if (value <= 35) return "HIGH";
    if (value <= 75) return "MEDIUM";

    return "LOW";
}

function generateCVSS(severity) {
    const ranges = {
        CRITICAL: [9.0, 10.0],
        HIGH: [7.0, 8.9],
        MEDIUM: [4.0, 6.9],
        LOW: [0.1, 3.9]
    };

    const [min, max] = ranges[severity];

    return faker.number.float({
        min,
        max,
        fractionDigits: 1
    });
}

function generateVulnerability(index) {
    const severity = generateSeverity();

    const publishedAt = faker.date.between({
        from: "2020-01-01T00:00:00.000Z",
        to: "2026-11-15T23:59:59.000Z"
    });

    return {
        cveId: `CVE-2026-${String(900000 + index).padStart(6, "0")}`,

        title: `${faker.hacker.verb()} ${faker.hacker.noun()} vulnerability in ${faker.helpers.arrayElement(PRODUCTS)}`,

        description: faker.lorem.paragraph(),

        severity,
        cvss: generateCVSS(severity),

        cweIds: faker.helpers.arrayElements(
            CWE_POOL,
            { min: 1, max: 3 }
        ),

        affectedProducts: faker.helpers.arrayElements(
            PRODUCTS,
            { min: 1, max: 4 }
        ),

        publishedAt,

        lastModifiedAt: faker.date.between({
            from: publishedAt,
            to: "2026-11-15T23:59:59.000Z"
        }),

        source: "CYBERTRACK_SIMULATED",

        status: faker.helpers.arrayElement([
            "ACTIVE",
            "MITIGATED",
            "CLOSED"
        ]),

        references: [
            `https://example.com/advisories/${900000 + index}`
        ]
    };
}

async function seedDatabase() {
    try {
        console.log("Connecting to MongoDB...");

        await mongoose.connect(process.env.MONGODB_URI);

        console.log("Connected successfully.");

        const collection = mongoose.connection.collection(
            "vulnerabilities"
        );

        const existingCount = await collection.countDocuments();

        if (existingCount > 0) {
            throw new Error(
                `Refusing to seed: vulnerabilities already contains ${existingCount} documents.`
            );
        }

        // Enforce unique vulnerability identifiers.
        await collection.createIndex(
            { cveId: 1 },
            { unique: true }
        );

        console.log("Generating vulnerability documents...");

        for (let start = 0; start < TOTAL_DOCUMENTS; start += BATCH_SIZE) {
            const batch = [];

            const end = Math.min(
                start + BATCH_SIZE,
                TOTAL_DOCUMENTS
            );

            for (let i = start; i < end; i++) {
                batch.push(generateVulnerability(i));
            }

            await collection.insertMany(batch, {
                ordered: true
            });

            console.log(
                `Inserted ${end}/${TOTAL_DOCUMENTS} documents`
            );
        }

        const total = await collection.countDocuments();

        console.log("--------------------------------");
        console.log("SEED COMPLETED");
        console.log(`Generated: ${TOTAL_DOCUMENTS}`);
        console.log(`Total vulnerabilities: ${total}`);
        console.log("--------------------------------");

    } catch (error) {
        console.error("Seed error:", error);
        process.exitCode = 1;

    } finally {
        await mongoose.disconnect();
    }
}

seedDatabase();
