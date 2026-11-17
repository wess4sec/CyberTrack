const mongoose = require("mongoose");
const AppError = require("./AppError");

async function assertReferencesExist(payload, references) {
    for (const reference of references) {
        let values = [payload[reference.field]];

        if (reference.array) {
            const items = payload[reference.field];

            if (items === undefined) {
                continue;
            }
            if (!Array.isArray(items)) {
                throw new AppError(400, `"${reference.field}" must be an array.`);
            }

            values = items.map(item => {
                if (!item || typeof item !== "object" || Array.isArray(item)) {
                    throw new AppError(
                        400,
                        `Each "${reference.field}" item must be an object.`
                    );
                }
                return item[reference.nestedField];
            });
        }

        for (const value of values) {
            if (value === undefined || value === null) {
                continue;
            }

            if (!mongoose.isObjectIdOrHexString(value)) {
                throw new AppError(
                    400,
                    `Invalid ObjectId in "${reference.field}".`
                );
            }

            const found = await reference.model.exists({ _id: value });

            if (!found) {
                throw new AppError(
                    400,
                    `Referenced document for "${reference.field}" does not exist.`
                );
            }
        }
    }
}

async function assertNoReferences(references) {
    for (const reference of references) {
        const found = await reference.model.exists(reference.filter);

        if (found) {
            throw new AppError(
                409,
                `Cannot delete this document while it is referenced by ${reference.label}.`
            );
        }
    }
}

module.exports = {
    assertNoReferences,
    assertReferencesExist
};
