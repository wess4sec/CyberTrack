// À exécuter dans mongosh avec : mongosh <URI> --file database/relationships.js
(() => {
    print("\n=== Scans avec assets et utilisateurs ===");
    // Cas : présenter le contexte d'un scan sans exposer de données de compte.
    // Sortie : { scanId, status, asset: { assetType, environment }, operatorRole }.
    db.getCollection("scans")
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
            { $unwind: { path: "$asset", preserveNullAndEmptyArrays: true } },
            { $unwind: { path: "$operator", preserveNullAndEmptyArrays: true } },
            {
                $project: {
                    _id: 0,
                    scanId: "$_id",
                    status: 1,
                    scanType: 1,
                    asset: {
                        assetType: "$asset.assetType",
                        environment: "$asset.environment"
                    },
                    operatorRole: "$operator.role"
                }
            },
            { $limit: 10 }
        ])
        .forEach(printjson);

    print("\n=== Résultats de scan intégrés et vulnérabilités référencées ===");
    // Cas : aplatir scans.results puis retrouver chaque vulnérabilité par ObjectId.
    // Sortie : { scanId, vulnerabilityId, title, port, severitySnapshot }.
    db.getCollection("scans")
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
            { $unwind: { path: "$vulnerability", preserveNullAndEmptyArrays: true } },
            {
                $project: {
                    _id: 0,
                    scanId: "$_id",
                    vulnerabilityId: "$results.vulnerabilityId",
                    title: "$vulnerability.title",
                    port: "$results.port",
                    severitySnapshot: "$results.severitySnapshot"
                }
            },
            { $limit: 10 }
        ])
        .forEach(printjson);

    print("\n=== Tâches de remédiation et documents référencés ===");
    // Cas : afficher vulnérabilité, asset, assigné et créateur d'une tâche.
    // Sortie : { taskTitle, status, vulnerability: {...}, asset: {...}, assigneeRole, creatorRole }.
    db.getCollection("remediation_tasks")
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
            { $unwind: { path: "$vulnerability", preserveNullAndEmptyArrays: true } },
            { $unwind: { path: "$asset", preserveNullAndEmptyArrays: true } },
            { $unwind: { path: "$assignee", preserveNullAndEmptyArrays: true } },
            { $unwind: { path: "$creator", preserveNullAndEmptyArrays: true } },
            {
                $project: {
                    _id: 0,
                    taskTitle: "$title",
                    status: 1,
                    vulnerability: {
                        cveId: "$vulnerability.cveId",
                        title: "$vulnerability.title"
                    },
                    assetType: "$asset.assetType",
                    assigneeRole: "$assignee.role",
                    creatorRole: "$creator.role"
                }
            },
            { $limit: 10 }
        ])
        .forEach(printjson);
})();
