const databaseName = "cybertrack_db";
const username = process.env.MONGO_APP_USERNAME;
const password = process.env.MONGO_APP_PASSWORD;

if (!username || !password) {
    throw new Error("MongoDB application credentials are required.");
}

const applicationDatabase = db.getSiblingDB(databaseName);
const existingUser = applicationDatabase.getUser(username);
const roles = [{ role: "readWrite", db: databaseName }];

if (existingUser) {
    print("Existing MongoDB application user is unchanged.");
} else {
    applicationDatabase.createUser({ user: username, pwd: password, roles });
}
