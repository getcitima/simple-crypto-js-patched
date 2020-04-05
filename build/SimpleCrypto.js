"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_js_1 = require("crypto-js");
var SimpleCrypto = /** @class */ (function () {
    function SimpleCrypto(secret) {
        if (secret === void 0) {
            throw new Error('SimpleCrypto object MUST BE initialised with a SECRET KEY.');
        }
        this._secret = secret;
        this._keySize = 256;
        this._iterations = 100;
        this._defaultEncoder = crypto_js_1.enc.Utf8;
    }
    SimpleCrypto.generateRandom = function (length, expectsWordArray) {
        if (length === void 0) { length = 128; }
        if (expectsWordArray === void 0) { expectsWordArray = false; }
        var random = crypto_js_1.lib.WordArray.random(length / 8);
        return expectsWordArray ? random : random.toString();
    };
    SimpleCrypto.prototype.encrypt = function (data) {
        if (data == void 0) {
            throw new Error('No data was attached to be encrypted. Encryption halted.');
        }
        var string = typeof data == "object"
            ? JSON.stringify(data)
            : typeof data == "string" || typeof data == "number" || typeof data == 'boolean'
                ? data.toString()
                : null;
        if (null === string) {
            throw new Error('Only object, string, number and boolean data types that can be encrypted.');
        }
        var salt = SimpleCrypto.generateRandom(128, true);
        // SHA256 the __secret. Secret should not be stored in plaintext and should always
        // be operated upon after hashing it.
        var hashedSecret = crypto_js_1.SHA256(this._secret);
        var key = crypto_js_1.PBKDF2(hashedSecret.toString(), salt, {
            keySize: this._keySize / 32,
            iterations: this._iterations
        });
        var initialVector = SimpleCrypto.generateRandom(128, true);
        var encrypted = crypto_js_1.AES.encrypt(string, key, {
            iv: initialVector,
            padding: crypto_js_1.pad.Pkcs7,
            mode: crypto_js_1.mode.CBC
        });
        // Combining the encrypted string with salt and IV to form ciphertext
        var ctxt = salt.toString() + initialVector.toString() + encrypted.toString();
        // Generate authentication tag and append that to the ciphertext using the key derived from PBKDF2.
        // (Optional TODO: Include a module to generate authentication key. Possibly HKDF-SHA256.)
        var hashedCtxt = crypto_js_1.HmacSHA256(ctxt, key).toString();
        return ctxt + hashedCtxt;
    };
    SimpleCrypto.prototype.decrypt = function (ciphered, expectsObject, encoder) {
        if (expectsObject === void 0) { expectsObject = false; }
        if (encoder === void 0) { encoder = this._defaultEncoder; }
        if (ciphered == void 0) {
            throw new Error('No encrypted string was attached to be decrypted. Decryption halted.');
        }
        var salt = crypto_js_1.enc.Hex.parse(ciphered.substr(0, 32));
        var initialVector = crypto_js_1.enc.Hex.parse(ciphered.substr(32, 32));
        var encrypted = ciphered.substring(64, ciphered.length - 64);
        // SHA256 the __secret
        var hashedSecret = crypto_js_1.SHA256(this._secret);
        var key = crypto_js_1.PBKDF2(hashedSecret.toString(), salt, {
            keySize: this._keySize / 32,
            iterations: this._iterations
        });
        // Before decryption, we need to authenticate using the MAC attached
        var hmac = ciphered.substring(ciphered.length - 64);
        var ctxt = ciphered.substring(0, ciphered.length - 64);
        if (hmac != crypto_js_1.HmacSHA256(ctxt, key).toString()) {
            throw new Error('Invalid encrypted text recieved. Please try again.');
        }
        var decrypted = crypto_js_1.AES.decrypt(encrypted, key, {
            iv: initialVector,
            padding: crypto_js_1.pad.Pkcs7,
            mode: crypto_js_1.mode.CBC
        });
        return expectsObject ? JSON.parse(decrypted.toString(encoder)) : decrypted.toString(encoder);
    };
    SimpleCrypto.prototype.encryptObject = function (object) {
        return this.encrypt(object);
    };
    SimpleCrypto.prototype.decryptObject = function (string) {
        var decrypted = this.decrypt(string, true);
        return typeof decrypted == 'object' ? decrypted : JSON.parse(decrypted);
    };
    SimpleCrypto.prototype.setSecret = function (secret) {
        this._secret = secret;
    };
    return SimpleCrypto;
}());
exports.SimpleCrypto = SimpleCrypto;
exports.default = SimpleCrypto;
//# sourceMappingURL=SimpleCrypto.js.map