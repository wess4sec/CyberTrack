const assert = require("node:assert/strict");
const mongoose = require("mongoose");
const {
    connectDatabase,
    disconnectDatabase
} = require("./connection");
const { validVulnerabilityExpression } = require("./validation");

const REQUIRED_COLLECTIONS = [
    "vulnerabilities",
    "assets",
    "users",
    "scans",
    "remediation_tasks"
];

function keyMatches(actual, expected) {
    const actualEntries = Object.entries(actual);
    const expectedEntries = Object.entries(expected);

    return (
        actualEntries.length === expectedEntries.length &&
        expectedEntries.every(
            ([field, direction], index) =>
                actualEntries[index][0] === field &&
                actualEntries[index][1] === direction
        )
    );
}

function collectPlanStages(value, stages = new Set()) {
    if (!value || typeof value !== "object") {
        return stages;
    }

    if (typeof value.stage === "string") {
        stages.add(value.stage);
    }

    for (const child of Object.values(value)) {
        if (Array.isArray(child)) {
            child.forEach(item => collectPlanStages(item, stages));
        } else if (child && typeof child === "object") {
            collectPlanStages(child, stages);
        }
    }

    return stages;
}

async function check(label, assertion) {
    await assertion();
    console.log(`PASS ${label}`);
}

async function run() {
    const database = await connectDatabase();

    try {
        const collectionNames = (
            await database.listCollections({}, { nameOnly: true }).toArray()
        ).map(collection => collection.name);

        await check("connexion et base cybertrack_db", async () => {
            assert.equal(database.databaseName, "cybertrack_db");
        });

        await check("les cinq collections attendues existent", async () => {
            for (const name of REQUIRED_COLLECTIONS) {
                assert.ok(
                    collectionNames.includes(name),
                    `Collection manquante : ${name}`
                );
            }
        });

        const vulnerabilities = database.collection("vulnerabilities");
        const vulnerabilityCount = await vulnerabilities.countDocuments();

        await check("au moins 10 000 vulnérabilités", async () => {
            assert.ok(vulnerabilityCount >= 10000);
        });

        await check("champs requis et valeurs conformes", async () => {
            const invalidCount = await vulnerabilities.countDocuments({
                $expr: { $not: [validVulnerabilityExpression()] }
            });
            assert.equal(invalidCount, 0);
        });

        const dateFields = [
            ["vulnerabilities", "publishedAt"],
            ["vulnerabilities", "lastModifiedAt"],
            ["assets", "createdAt"],
            ["users", "createdAt"],
            ["scans", "startedAt"],
            ["scans", "completedAt"],
            ["scans", "results.detectedAt"],
            ["remediation_tasks", "createdAt"],
            ["remediation_tasks", "dueDate"],
            ["remediation_tasks", "history.changedAt"]
        ];

        await check("champs de date stockés en BSON Date", async () => {
            for (const [collectionName, field] of dateFields) {
                const invalidCount = await database
                    .collection(collectionName)
                    .countDocuments({
                        [field]: { $not: { $type: "date" } }
                    });
                assert.equal(
                    invalidCount,
                    0,
                    `${collectionName}.${field} contient une valeur non-Date`
                );
            }
        });

        const arrayFields = [
            ["vulnerabilities", "cweIds"],
            ["vulnerabilities", "affectedProducts"],
            ["vulnerabilities", "references"],
            ["assets", "tags"],
            ["scans", "results"],
            ["remediation_tasks", "history"]
        ];

        await check("champs tableaux présents et de type array", async () => {
            for (const [collectionName, field] of arrayFields) {
                const invalidCount = await database
                    .collection(collectionName)
                    .countDocuments({
                        [field]: { $not: { $type: "array" } }
                    });
                assert.equal(
                    invalidCount,
                    0,
                    `${collectionName}.${field} manque ou n'est pas un tableau`
                );
            }

            assert.ok(
                (await database
                    .collection("scans")
                    .countDocuments({ "results.0": { $exists: true } })) > 0,
                "Aucun résultat de scan intégré trouvé"
            );
        });

        await check("références des scans et des tâches résolues", async () => {
            const scanCount = await database.collection("scans").countDocuments();
            const resolvedScans = await database
                .collection("scans")
                .aggregate([
                    {
                        $lookup: {
                            from: "assets",
                            localField: "assetId",
                            foreignField: "_id",
                            as: "asset"
                        }
                    },
                    {
                        $lookup: {
                            from: "users",
                            localField: "scannedBy",
                            foreignField: "_id",
                            as: "operator"
                        }
                    },
                    {
                        $match: {
                            "asset.0": { $exists: true },
                            "operator.0": { $exists: true }
                        }
                    },
                    { $count: "count" }
                ])
                .toArray();

            assert.equal(resolvedScans[0] ? resolvedScans[0].count : 0, scanCount);

            const taskCount = await database
                .collection("remediation_tasks")
                .countDocuments();
            const resolvedTasks = await database
                .collection("remediation_tasks")
                .aggregate([
                    {
                        $lookup: {
                            from: "vulnerabilities",
                            localField: "vulnerabilityId",
                            foreignField: "_id",
                            as: "vulnerability"
                        }
                    },
                    {
                        $lookup: {
                            from: "assets",
                            localField: "assetId",
                            foreignField: "_id",
                            as: "asset"
                        }
                    },
                    {
                        $lookup: {
                            from: "users",
                            localField: "assignedTo",
                            foreignField: "_id",
                            as: "assignee"
                        }
                    },
                    {
                        $lookup: {
                            from: "users",
                            localField: "createdBy",
                            foreignField: "_id",
                            as: "creator"
                        }
                    },
                    {
                        $match: {
                            "vulnerability.0": { $exists: true },
                            "asset.0": { $exists: true },
                            "assignee.0": { $exists: true },
                            "creator.0": { $exists: true }
                        }
                    },
                    { $count: "count" }
                ])
                .toArray();

            assert.equal(resolvedTasks[0] ? resolvedTasks[0].count : 0, taskCount);
        });

        await check("index uniques, de recherche et de références présents", async () => {
            const vulnerabilityIndexes = await vulnerabilities.indexes();
            const hasIndex = (indexes, key, unique) =>
                indexes.some(
                    index =>
                        keyMatches(index.key, key) &&
                        (unique === undefined || index.unique === unique)
                );

            assert.ok(
                hasIndex(vulnerabilityIndexes, { cveId: 1 }, true),
                "Index unique cveId absent"
            );
            assert.ok(hasIndex(vulnerabilityIndexes, { severity: 1 }));
            assert.ok(
                hasIndex(vulnerabilityIndexes, { severity: 1, cvss: -1 })
            );
            assert.ok(hasIndex(vulnerabilityIndexes, { publishedAt: -1 }));
            assert.ok(
                vulnerabilityIndexes.some(
                    index =>
                        index.name === "vulnerability_text_index" &&
                        index.weights.title === 5 &&
                        index.weights.description === 1
                ),
                "Index texte title/description absent ou différent"
            );

            const scanIndexes = await database.collection("scans").indexes();
            assert.ok(hasIndex(scanIndexes, { assetId: 1 }));
            assert.ok(hasIndex(scanIndexes, { scannedBy: 1 }));
            assert.ok(
                hasIndex(scanIndexes, { "results.vulnerabilityId": 1 }),
                "Index des vulnérabilités trouvées par scan absent"
            );

            const taskIndexes = await database
                .collection("remediation_tasks")
                .indexes();
            assert.ok(
                hasIndex(taskIndexes, { vulnerabilityId: 1, assetId: 1 })
            );
            assert.ok(hasIndex(taskIndexes, { assetId: 1 }));
            assert.ok(hasIndex(taskIndexes, { assignedTo: 1 }));
            assert.ok(hasIndex(taskIndexes, { createdBy: 1 }));
        });

        await check("validation stricte refuse un document invalide", async () => {
            const [info] = await database
                .listCollections({ name: "vulnerabilities" })
                .toArray();
            assert.equal(info.options.validationLevel, "strict");
            assert.equal(info.options.validationAction, "error");

            const testId = new mongoose.Types.ObjectId();

            try {
                await vulnerabilities.insertOne({
                    _id: testId,
                    title: "CyberTrack validation test",
                    severity: "LOW",
                    cvss: 11,
                    publishedAt: new Date()
                });
            } catch (error) {
                assert.equal(
                    error.code,
                    121,
                    `Échec inattendu du test de validation: ${error.message}`
                );
                return;
            }

            const cleanup = await vulnerabilities.deleteOne({ _id: testId });

            if (cleanup.deletedCount !== 1) {
                throw new Error(
                    "Un document de test non valide a été accepté et n'a pas pu être retiré."
                );
            }

            assert.fail("Le validateur a accepté un CVSS supérieur à 10.");
        });

        await check("pipelines de statistiques, facettes et fenêtrage", async () => {
            const monthly = await vulnerabilities
                .aggregate([
                    {
                        $group: {
                            _id: {
                                year: { $year: "$publishedAt" },
                                month: { $month: "$publishedAt" }
                            },
                            count: { $sum: 1 },
                            average: { $avg: "$cvss" },
                            minimum: { $min: "$cvss" },
                            maximum: { $max: "$cvss" }
                        }
                    },
                    { $sort: { "_id.year": 1, "_id.month": 1 } },
                    { $limit: 3 }
                ])
                .toArray();
            assert.ok(Array.isArray(monthly));
            assert.ok(monthly.length > 0);

            const advanced = await vulnerabilities
                .aggregate([
                    {
                        $facet: {
                            severity: [
                                {
                                    $group: {
                                        _id: "$severity",
                                        count: { $sum: 1 }
                                    }
                                }
                            ],
                            cvssBands: [
                                {
                                    $bucket: {
                                        groupBy: "$cvss",
                                        boundaries: [0, 4, 7, 9, 10.01],
                                        default: "other",
                                        output: { count: { $sum: 1 } }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $project: {
                            severity: 1,
                            cvssBands: 1,
                            computed: {
                                $switch: {
                                    branches: [
                                        {
                                            case: { $gt: [{ $size: "$severity" }, 0] },
                                            then: "ready"
                                        }
                                    ],
                                    default: "empty"
                                }
                            }
                        }
                    }
                ])
                .toArray();
            assert.equal(advanced.length, 1);
            assert.equal(advanced[0].computed, "ready");

            const windowed = await vulnerabilities
                .aggregate([
                    {
                        $setWindowFields: {
                            partitionBy: "$severity",
                            sortBy: { cvss: -1 },
                            output: {
                                averageToDate: {
                                    $avg: "$cvss",
                                    window: {
                                        documents: ["unbounded", "current"]
                                    }
                                }
                            }
                        }
                    },
                    { $limit: 3 }
                ])
                .toArray();
            assert.equal(windowed.length, 3);
        });

        await check("pipelines de relations et résultats de scan", async () => {
            const scanResults = await database
                .collection("scans")
                .aggregate([
                    { $unwind: "$results" },
                    {
                        $lookup: {
                            from: "vulnerabilities",
                            localField: "results.vulnerabilityId",
                            foreignField: "_id",
                            as: "vulnerability"
                        }
                    },
                    { $limit: 5 }
                ])
                .toArray();
            assert.ok(scanResults.length > 0);

            const joinedScans = await database
                .collection("scans")
                .aggregate([
                    {
                        $lookup: {
                            from: "assets",
                            localField: "assetId",
                            foreignField: "_id",
                            as: "asset"
                        }
                    },
                    {
                        $lookup: {
                            from: "users",
                            localField: "scannedBy",
                            foreignField: "_id",
                            as: "operator"
                        }
                    }
                ])
                .toArray();
            assert.ok(joinedScans.length > 0);
        });

        await check("comparaison réelle COLLSCAN / IXSCAN", async () => {
            const filter = { severity: "CRITICAL" };
            const collection = vulnerabilities;
            const scanExplain = await collection
                .find(filter)
                .hint({ $natural: 1 })
                .explain("executionStats");
            const indexExplain = await collection
                .find(filter)
                .hint("severity_index")
                .explain("executionStats");

            const scanStages = collectPlanStages(scanExplain.queryPlanner.winningPlan);
            const indexStages = collectPlanStages(indexExplain.queryPlanner.winningPlan);
            const scanStats = scanExplain.executionStats;
            const indexStats = indexExplain.executionStats;

            assert.ok(scanStages.has("COLLSCAN"), "Plan de référence sans COLLSCAN");
            assert.ok(indexStages.has("IXSCAN"), "Plan indexé sans IXSCAN");
            assert.equal(scanStats.nReturned, indexStats.nReturned);

            console.log(
                "EXPLAIN executionStats (mesures réelles; COLLSCAN forcé puis index severity_index):"
            );
            console.log(
                JSON.stringify(
                    {
                        COLLSCAN: {
                            nReturned: scanStats.nReturned,
                            totalDocsExamined: scanStats.totalDocsExamined,
                            totalKeysExamined: scanStats.totalKeysExamined,
                            executionTimeMillis: scanStats.executionTimeMillis
                        },
                        IXSCAN: {
                            nReturned: indexStats.nReturned,
                            totalDocsExamined: indexStats.totalDocsExamined,
                            totalKeysExamined: indexStats.totalKeysExamined,
                            executionTimeMillis: indexStats.executionTimeMillis
                        }
                    },
                    null,
                    2
                )
            );
        });

        console.log(`\nVérification terminée : ${vulnerabilityCount} vulnérabilités.`);
    } finally {
        await disconnectDatabase();
    }
}

run().catch(error => {
    console.error("Vérification MongoDB échouée:", error.message);
    process.exitCode = 1;
});
