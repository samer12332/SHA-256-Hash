"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
function generateSalt(length) {
    return crypto_1.default.randomBytes(length).toString('hex');
}
function hash(password, salt) {
    const hash = crypto_1.default.createHash('sha256');
    hash.update(password + salt);
    return salt + ':' + hash.digest('hex');
}
function compare(password, hashed) {
    const [salt, originalHash] = hashed.split(':');
    const hash = crypto_1.default.createHash('sha256');
    hash.update(password + salt);
    const newHash = hash.digest('hex');
    return newHash === originalHash;
}
const hashedPassword = hash('samer99yousry', generateSalt(16));
console.log(compare('samer99yousry', hashedPassword));
