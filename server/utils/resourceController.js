const AppError = require("./AppError");
const asyncHandler = require("./asyncHandler");
const {
    assertAllowedQuery,
    parseInteger,
    parseObjectId,
    pickBodyFields,
    safeSerialize
} = require("./requestValidation");
const { assertReferencesExist } = require("./references");

function createResourceController({
    Model,
    writableFields,
    queryFields = [],
    sortFields,
    defaultSort = "_id",
    populate = [],
    buildFilter = () => ({}),
    references = [],
    beforeDelete,
    prepareCreate = payload => payload,
    prepareUpdate = payload => payload
}) {
    const allowedQueryFields = [
        "page",
        "limit",
        "sort",
        "order",
        ...queryFields
    ];

    const list = asyncHandler(async (request, response) => {
        assertAllowedQuery(request.query, allowedQueryFields);

        const page = parseInteger(request.query.page, "page", {
            defaultValue: 1,
            min: 1,
            max: 1000000
        });
        const limit = parseInteger(request.query.limit, "limit", {
            defaultValue: 20,
            min: 1,
            max: 100
        });
        const sortField = request.query.sort || defaultSort;
        const order = request.query.order || "desc";

        if (!sortFields.includes(sortField)) {
            throw new AppError(
                400,
                `Unsupported sort field. Allowed: ${sortFields.join(", ")}.`
            );
        }
        if (order !== "asc" && order !== "desc") {
            throw new AppError(400, 'Query parameter "order" must be asc or desc.');
        }

        const filter = buildFilter(request.query);
        const sort = { [sortField]: order === "asc" ? 1 : -1 };

        if (sortField !== "_id") {
            sort._id = 1;
        }

        const [documents, total] = await Promise.all([
            Model.find(filter)
                .populate(populate)
                .sort(sort)
                .skip((page - 1) * limit)
                .limit(limit)
                .exec(),
            Model.countDocuments(filter)
        ]);

        response.status(200).json({
            success: true,
            data: safeSerialize(documents),
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    });

    const getById = asyncHandler(async (request, response) => {
        const id = parseObjectId(request.params.id);
        const document = await Model.findById(id).populate(populate).exec();

        if (!document) {
            throw new AppError(404, "Resource not found.");
        }

        response.status(200).json({
            success: true,
            data: safeSerialize(document)
        });
    });

    const create = asyncHandler(async (request, response) => {
        const input = pickBodyFields(request.body, writableFields);
        const payload = await prepareCreate(input);
        await assertReferencesExist(payload, references);
        const document = await Model.create(payload);

        response.status(201).json({
            success: true,
            data: safeSerialize(document)
        });
    });

    const update = asyncHandler(async (request, response) => {
        const id = parseObjectId(request.params.id);
        const input = pickBodyFields(request.body, writableFields);
        const payload = await prepareUpdate(input);
        await assertReferencesExist(payload, references);
        const document = await Model.findById(id).exec();

        if (!document) {
            throw new AppError(404, "Resource not found.");
        }

        document.set(payload);
        await document.save();

        const updatedDocument = await Model.findById(id)
            .populate(populate)
            .exec();

        response.status(200).json({
            success: true,
            data: safeSerialize(updatedDocument)
        });
    });

    const remove = asyncHandler(async (request, response) => {
        const id = parseObjectId(request.params.id);
        const document = await Model.findById(id).exec();

        if (!document) {
            throw new AppError(404, "Resource not found.");
        }

        if (beforeDelete) {
            await beforeDelete(id);
        }

        await document.deleteOne();

        response.status(200).json({
            success: true,
            data: { id: String(id), deleted: true }
        });
    });

    return { list, getById, create, update, remove };
}

module.exports = createResourceController;
