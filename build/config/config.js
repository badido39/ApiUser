"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
var MONGO_OPTIONS = {
    useUnifiedTopology: true,
    useNewUrlParser: true,
    socketTimeoutMS: 30000,
    keepAlive: true,
    poolSize: 50,
    autoIndex: false,
    retryWrites: true
};
var MONGO_USERNAME = process.env.MONGO_USERNAME || '';
var MONGO_PASSWORD = process.env.MONGO_PASSWORD || '';
var MONGO_HOST = process.env.MONGO_URL || "";
var MONGO = {
    host: MONGO_HOST,
    password: MONGO_PASSWORD,
    username: MONGO_USERNAME,
    options: MONGO_OPTIONS,
    //url: `mongodb://localhost:27017`
    url: "mongodb+srv://".concat(MONGO_USERNAME, ":").concat(MONGO_PASSWORD, "@").concat(MONGO_HOST)
};
var SERVER_HOSTNAME = process.env.SERVER_HOSTNAME || '';
var SERVER_PORT = process.env.SERVER_PORT || 1337;
var SERVER_TOKEN_EXPIRETIME = process.env.SERVER_TOKEN_EXPIRETIME || 3600;
var SERVER_TOKEN_ISSUER = process.env.SERVER_TOKEN_ISSUER || '';
var SERVER_TOKEN_SECRET = process.env.SERVER_TOKEN_SECRET || '';
var SERVER = {
    hostname: SERVER_HOSTNAME,
    port: SERVER_PORT,
    token: {
        expireTime: SERVER_TOKEN_EXPIRETIME,
        issuer: SERVER_TOKEN_ISSUER,
        secret: SERVER_TOKEN_SECRET
    }
};
var config = {
    mongo: MONGO,
    server: SERVER
};
exports.default = config;
