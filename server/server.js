const app = require("./app");
const {
    connectDatabase,
    disconnectDatabase
} = require("./config/database");
const { getJwtSecret } = require("./config/auth");
const { writeLog } = require("./utils/logger");

function getPort() {
    const value = process.env.PORT || "5000";

    if (!/^\d+$/.test(value)) {
        throw new Error("PORT must be an integer between 1 and 65535.");
    }

    const port = Number(value);

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error("PORT must be an integer between 1 and 65535.");
    }

    return port;
}

async function startServer() {
    getJwtSecret();
    await connectDatabase();

    const host = process.env.HOST || "127.0.0.1";
    const port = getPort();

    return new Promise((resolve, reject) => {
        const server = app.listen(port, host);

        server.once("listening", () => {
            writeLog("info", "server_started", { host, port });
            resolve(server);
        });

        server.once("error", async error => {
            await disconnectDatabase();
            reject(error);
        });
    });
}

if (require.main === module) {
    startServer()
        .then(server => {
            let shuttingDown = false;

            const shutdown = signal => {
                if (shuttingDown) return;
                shuttingDown = true;
                writeLog("info", "server_shutdown_started", { signal });
                server.close(async error => {
                    if (error) {
                        writeLog("error", "http_server_shutdown_failed", {
                            errorName: error.name
                        });
                        process.exitCode = 1;
                    }
                    try {
                        await disconnectDatabase();
                    } catch (disconnectError) {
                        writeLog("error", "mongodb_disconnect_failed", {
                            errorName: disconnectError.name
                        });
                        process.exitCode = 1;
                    }
                });
            };

            process.once("SIGINT", () => shutdown("SIGINT"));
            process.once("SIGTERM", () => shutdown("SIGTERM"));
        })
        .catch(async error => {
            writeLog("error", "api_startup_failed", {
                errorName: error.name || "Error"
            });
            process.exitCode = 1;
            await disconnectDatabase();
        });
}

module.exports = { startServer };
