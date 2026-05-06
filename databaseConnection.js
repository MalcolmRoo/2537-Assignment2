require('dotenv').config();

const mongodb_host = process.env.HOST;
const mongodb_user = process.env.USER;
const mongodb_password = process.env.DATABASE_PASS;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
var database = new MongoClient(atlasURI, {});
module.exports = {database};