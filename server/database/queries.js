// À exécuter dans mongosh avec : mongosh <URI> --file database/queries.js
(() => {
    const vulnerabilities = db.getCollection("vulnerabilities");

    print("\n=== Requêtes de base : vulnérabilités critiques ===");
    // Cas : afficher les cinq vulnérabilités critiques les plus sévères.
    // Projection, tri et limite évitent de transférer des documents inutiles.
    // Sortie : { cveId, title, severity, cvss }.
    vulnerabilities
        .find(
            { severity: "CRITICAL" },
            { _id: 0, cveId: 1, title: 1, severity: 1, cvss: 1 }
        )
        .sort({ cvss: -1, publishedAt: -1 })
        .limit(5)
        .forEach(printjson);

    print("\n=== Opérateurs numériques : $gt, $gte et $lt ===");
    // Cas : repérer les scores très élevés ou situés dans une plage donnée.
    // Sortie : { cveId, cvss }.
    vulnerabilities
        .find(
            { cvss: { $gt: 9 } },
            { _id: 0, cveId: 1, cvss: 1 }
        )
        .limit(5)
        .forEach(printjson);
    vulnerabilities
        .find(
            { cvss: { $gte: 7, $lt: 9 } },
            { _id: 0, cveId: 1, cvss: 1 }
        )
        .limit(5)
        .forEach(printjson);

    print("\n=== Opérateurs d'ensemble : $in et $ne ===");
    // Cas : filtrer les niveaux importants, puis exclure un statut.
    // Sortie : { cveId, severity, status }.
    vulnerabilities
        .find(
            { severity: { $in: ["CRITICAL", "HIGH"] }, status: { $ne: "CLOSED" } },
            { _id: 0, cveId: 1, severity: 1, status: 1 }
        )
        .limit(5)
        .forEach(printjson);

    print("\n=== Recherche textuelle simple : $regex ===");
    // Cas : retrouver les titres qui mentionnent un produit.
    // Sortie : { cveId, title }; une regex non ancrée peut parcourir les documents.
    vulnerabilities
        .find(
            { title: { $regex: "nginx", $options: "i" } },
            { _id: 0, cveId: 1, title: 1 }
        )
        .limit(5)
        .forEach(printjson);

    print("\n=== Tableau imbriqué : $elemMatch ===");
    // Cas : trouver un scan ayant au moins un résultat critique sur un port.
    // Sortie : { _id, assetId, results: [...] }.
    db.getCollection("scans")
        .find(
            {
                results: {
                    $elemMatch: {
                        severitySnapshot: "CRITICAL",
                        port: { $gte: 1 }
                    }
                }
            },
            { assetId: 1, results: 1 }
        )
        .limit(5)
        .forEach(printjson);

    print("\n=== Agrégation : $match, $group, $project, $sort, $limit ===");
    // Cas : tableau de bord des sévérités et statistiques CVSS.
    // Sortie : { severity, count, averageCvss, minCvss, maxCvss }.
    vulnerabilities.aggregate([
        { $match: { cvss: { $gte: 0, $lte: 10 } } },
        {
            $group: {
                _id: "$severity",
                count: { $sum: 1 },
                averageCvss: { $avg: "$cvss" },
                minCvss: { $min: "$cvss" },
                maxCvss: { $max: "$cvss" }
            }
        },
        {
            $project: {
                _id: 0,
                severity: "$_id",
                count: 1,
                averageCvss: { $round: ["$averageCvss", 2] },
                minCvss: 1,
                maxCvss: 1
            }
        },
        { $sort: { count: -1 } },
        { $limit: 4 }
    ]).forEach(printjson);

    print("\n=== Date : $year et $month ===");
    // Cas : suivre le nombre de vulnérabilités publiées par mois.
    // Sortie : { year, month, count }, trié chronologiquement.
    vulnerabilities.aggregate([
        {
            $group: {
                _id: {
                    year: { $year: "$publishedAt" },
                    month: { $month: "$publishedAt" }
                },
                count: { $sum: 1 }
            }
        },
        {
            $project: {
                _id: 0,
                year: "$_id.year",
                month: "$_id.month",
                count: 1
            }
        },
        { $sort: { year: 1, month: 1 } },
        { $limit: 12 }
    ]).forEach(printjson);

    print("\n=== Agrégation avancée : $facet ===");
    // Cas : fournir en une requête les statistiques globales et les cas critiques.
    // Sortie : un document { bySeverity: [...], critical: [...] }.
    vulnerabilities.aggregate([
        {
            $facet: {
                bySeverity: [
                    { $group: { _id: "$severity", count: { $sum: 1 } } },
                    { $sort: { count: -1 } }
                ],
                critical: [
                    { $match: { severity: "CRITICAL" } },
                    { $sort: { cvss: -1 } },
                    { $limit: 5 },
                    { $project: { _id: 0, cveId: 1, title: 1, cvss: 1 } }
                ]
            }
        }
    ]).forEach(printjson);

    print("\n=== Agrégation avancée : $bucket ===");
    // Cas : répartir les vulnérabilités par bandes de score CVSS.
    // Sortie : { _id: borneBasse, count, averageCvss }.
    vulnerabilities.aggregate([
        {
            $bucket: {
                groupBy: "$cvss",
                boundaries: [0, 4, 7, 9, 10.01],
                default: "hors_plage",
                output: {
                    count: { $sum: 1 },
                    averageCvss: { $avg: "$cvss" }
                }
            }
        },
        { $sort: { _id: 1 } }
    ]).forEach(printjson);

    print("\n=== Agrégation avancée : $addFields et $switch ===");
    // Cas : calculer une priorité de traitement sans modifier les documents.
    // Sortie : { cveId, severity, responsePriority }.
    vulnerabilities.aggregate([
        {
            $addFields: {
                responsePriority: {
                    $switch: {
                        branches: [
                            { case: { $eq: ["$severity", "CRITICAL"] }, then: 1 },
                            { case: { $eq: ["$severity", "HIGH"] }, then: 2 },
                            { case: { $eq: ["$severity", "MEDIUM"] }, then: 3 }
                        ],
                        default: 4
                    }
                }
            }
        },
        { $sort: { responsePriority: 1, cvss: -1 } },
        { $limit: 5 },
        {
            $project: {
                _id: 0,
                cveId: 1,
                severity: 1,
                responsePriority: 1
            }
        }
    ]).forEach(printjson);

    print("\n=== Fenêtre : $setWindowFields ===");
    // Cas : calculer une moyenne CVSS cumulative dans chaque sévérité.
    // Sortie : { cveId, severity, cvss, runningAverage }.
    vulnerabilities.aggregate([
        {
            $setWindowFields: {
                partitionBy: "$severity",
                sortBy: { cvss: -1 },
                output: {
                    runningAverage: {
                        $avg: "$cvss",
                        window: { documents: ["unbounded", "current"] }
                    }
                }
            }
        },
        { $limit: 5 },
        {
            $project: {
                _id: 0,
                cveId: 1,
                severity: 1,
                cvss: 1,
                runningAverage: { $round: ["$runningAverage", 2] }
            }
        }
    ]).forEach(printjson);
})();
