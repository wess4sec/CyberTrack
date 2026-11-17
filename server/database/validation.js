const {
    connectDatabase,
    disconnectDatabase
} = require("./connection");

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const VULNERABILITY_SCHEMA = {
    bsonType: "object",
    required: ["cveId", "title", "severity", "cvss", "publishedAt"],
    properties: {
        cveId: {
            bsonType: "string",
            minLength: 1
        },
        title: {
            bsonType: "string",
            minLength: 1
        },
        severity: {
            enum: SEVERITIES
        },
        cvss: {
            bsonType: ["double", "int", "long", "decimal"],
            minimum: 0,
            maximum: 10
        },
        publishedAt: {
            bsonType: "date"
        }
    }
};

function isNonEmptyString(field) {
    return {
        $cond: [
            { $eq: [{ $type: `$${field}` }, "string"] },
            { $gt: [{ $strLenCP: `$${field}` }, 0] },
            false
        ]
    };
}

function validVulnerabilityExpression() {
    return {
        $and: [
            isNonEmptyString("cveId"),
            isNonEmptyString("title"),
            { $in: ["$severity", SEVERITIES] },
            {
                $and: [
                    { $isNumber: "$cvss" },
                    { $gte: ["$cvss", 0] },
                    { $lte: ["$cvss", 10] }
                ]
            },
            { $eq: [{ $type: "$publishedAt" }, "date"] }
        ]
    };
}

function containsLabSchema(validator) {
    if (!validator || typeof validator !== "object") {
        return false;
    }

    const schema = validator.$jsonSchema;
    const properties = schema && schema.properties;

    if (
        properties &&
        properties.cveId &&
        properties.title &&
        properties.cvss
    ) {
        return (
            properties.cveId.minLength === 1 &&
            properties.title.minLength === 1 &&
            properties.cvss.minimum === 0 &&
            properties.cvss.maximum === 10 &&
            schema.required &&
            VULNERABILITY_SCHEMA.required.every(field =>
                schema.required.includes(field)
            )
        );
    }

    return Array.isArray(validator.$and) &&
        validator.$and.some(containsLabSchema);
}

async function run() {
    const database = await connectDatabase();

    try {
        const collection = database.collection("vulnerabilities");
        const invalidCount = await collection.countDocuments({
            $expr: { $not: [validVulnerabilityExpression()] }
        });

        if (invalidCount > 0) {
            throw new Error(
                `Refusing to change validation: ${invalidCount} existing vulnerability documents do not satisfy the requested schema.`
            );
        }

        const duplicates = await collection
            .aggregate([
                { $group: { _id: "$cveId", count: { $sum: 1 } } },
                { $match: { count: { $gt: 1 } } },
                { $limit: 1 }
            ])
            .toArray();

        if (duplicates.length > 0) {
            throw new Error(
                "Refusing to change validation: duplicate cveId values exist."
            );
        }

        const [collectionInfo] = await database
            .listCollections({ name: "vulnerabilities" })
            .toArray();
        const currentValidator =
            collectionInfo.options && collectionInfo.options.validator;

        let validator = { $jsonSchema: VULNERABILITY_SCHEMA };

        if (currentValidator && !containsLabSchema(currentValidator)) {
            validator = {
                $and: [
                    currentValidator,
                    { $jsonSchema: VULNERABILITY_SCHEMA }
                ]
            };
        } else if (currentValidator && containsLabSchema(currentValidator)) {
            validator = currentValidator;
        }

        await database.command({
            collMod: "vulnerabilities",
            validator,
            validationLevel: "strict",
            validationAction: "error"
        });

        const [updatedInfo] = await database
            .listCollections({ name: "vulnerabilities" })
            .toArray();

        if (
            updatedInfo.options.validationLevel !== "strict" ||
            updatedInfo.options.validationAction !== "error"
        ) {
            throw new Error("Strict/error validation was not applied.");
        }

        console.log(
            "Strict JSON Schema validation is active; existing documents were not modified."
        );
        console.log(
            `Preflight passed for ${await collection.countDocuments()} vulnerabilities.`
        );
    } finally {
        await disconnectDatabase();
    }
}

module.exports = {
    VULNERABILITY_SCHEMA,
    validVulnerabilityExpression
};

if (require.main === module) {
    run().catch(error => {
        console.error("Validation setup failed:", error.message);
        process.exitCode = 1;
    });
}
