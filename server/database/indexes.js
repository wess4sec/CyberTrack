const {
    connectDatabase,
    disconnectDatabase
} = require("./connection");

const INDEXES = [
    {
        collection: "vulnerabilities",
        key: { cveId: 1 },
        options: { unique: true }
    },
    {
        collection: "vulnerabilities",
        key: { severity: 1 },
        options: { name: "severity_index" }
    },
    {
        collection: "vulnerabilities",
        key: { severity: 1, cvss: -1 },
        options: { name: "severity_cvss_index" }
    },
    {
        collection: "vulnerabilities",
        key: { publishedAt: -1 },
        options: { name: "published_date_index" }
    },
    {
        collection: "vulnerabilities",
        key: { title: "text", description: "text" },
        options: {
            name: "vulnerability_text_index",
            weights: { title: 5, description: 1 }
        }
    },
    {
        collection: "scans",
        key: { assetId: 1 }
    },
    {
        collection: "scans",
        key: { scannedBy: 1 }
    },
    {
        collection: "scans",
        key: { "results.vulnerabilityId": 1 },
        options: { name: "scan_result_vulnerability_index" }
    },
    {
        collection: "remediation_tasks",
        key: { vulnerabilityId: 1, assetId: 1 }
    },
    {
        collection: "remediation_tasks",
        key: { assetId: 1 }
    },
    {
        collection: "remediation_tasks",
        key: { assignedTo: 1 }
    },
    {
        collection: "remediation_tasks",
        key: { createdBy: 1 }
    }
];

async function run() {
    const database = await connectDatabase();

    try {
        for (const index of INDEXES) {
            await database
                .collection(index.collection)
                .createIndex(index.key, index.options || {});
        }

        const summary = {};

        for (const name of ["vulnerabilities", "scans", "remediation_tasks"]) {
            summary[name] = (await database.collection(name).indexes()).map(
                index => index.name
            );
        }

        console.log("Index creation/verification completed.");
        console.log(JSON.stringify(summary, null, 2));
    } finally {
        await disconnectDatabase();
    }
}

run().catch(error => {
    console.error("Index setup failed:", error.message);
    process.exitCode = 1;
});
