const AppError = require("../utils/AppError");

function notFound(_request, _response, next) {
    next(
        new AppError(
            404,
            "Route not found."
        )
    );
}

module.exports = notFound;
