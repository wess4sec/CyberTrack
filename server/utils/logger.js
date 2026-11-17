function writeLog(level, event, fields = {}) {
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        event,
        ...fields
    };

    const output = JSON.stringify(entry);

    if (level === "error") {
        console.error(output);
    } else {
        console.log(output);
    }
}

function requestLogger(request, response, next) {
    if (process.env.NODE_ENV === "test") {
        next();
        return;
    }

    const startedAt = process.hrtime.bigint();

    response.once("finish", () => {
        const durationMs =
            Number(process.hrtime.bigint() - startedAt) / 1_000_000;

        writeLog("info", "http_request", {
            method: request.method,
            path: request.path,
            statusCode: response.statusCode,
            durationMs: Math.round(durationMs * 100) / 100
        });
    });

    next();
}

module.exports = {
    requestLogger,
    writeLog
};
