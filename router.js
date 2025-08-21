const ed = require('@noble/ed25519');
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const {sha512} = require("@noble/hashes/sha2");
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const USER_EMAIL = "user@example.com";

const STORAGE  = {
    publicKeys: {},
    validateCodes: {},
    challenges: {}
}

const DISABLE_LOGGER = false;

const Logger = {
    e: (...args) => !DISABLE_LOGGER && console.error(...args) ? args : undefined,
    w: (...args) => !DISABLE_LOGGER && console.warn(...args) ? args : undefined,
    m: (...args) => !DISABLE_LOGGER && console.log(...args) ? args : undefined,
};

function generateSixDigitNumber() {
    return Math.floor(Math.random() * 900000) + 100000;
}

const getNonce = (signature, key) => {
    const nonceKeys = Object.keys(STORAGE.challenges);

    const nonce = nonceKeys.find(nonceKey => {
        Logger.m("Verifying signature", signature, "for nonce", nonceKey, "with key", key);
        let verifyResult;
        try {
            verifyResult = ed.verify(signature, new TextEncoder().encode(nonceKey), key);
        } catch (e) {
            Logger.e(e);
        }
        Logger.m("Verification", verifyResult ? "successful" : "failed");
        return verifyResult;
    })
    if (!nonce) {
        return null;
    }

    return STORAGE.challenges[nonce];
}

const isTokenValid = function (signedJWTString, secretOrPublicKey, options) {
    try {
        const {nonce, expires} = getNonce(signedJWTString, secretOrPublicKey) ?? {};

        if (!nonce || !expires) {
            return false;
        }

        delete STORAGE.challenges[nonce];
        const nonceExpired = expires < Date.now();

        if (nonceExpired) {
            Logger.m("Challenge expired, removed from storage")
        } else {
            Logger.m("Challenge success, removed from storage")
        }

        return !nonceExpired;
    } catch (e) {
        return false;
    }
}

router.post("/resend_validate_code", (req, res) => {
    const {email} = req.body ?? {};
    if (!email) {
        return res.status(401).send()
    }
    const randomCode = generateSixDigitNumber();
    STORAGE.validateCodes[email] ??= [];
    STORAGE.validateCodes[email].push(randomCode);
    console.log("Generated new validation code:", randomCode, "for email", email);
    res.status(200).send()
})

router.get("/request_biometric_challenge", (req, res) => {
    Logger.m("Requested biometric challenge")
    if (!STORAGE.publicKeys[USER_EMAIL]) {
        return res.status(401).send(Logger.w("Registration required"))
    }
    const nonce = ed.etc.bytesToHex(ed.etc.randomBytes(16));
    const expirationDate = Date.now() + 10 * 1000 * 60; // 10 minutes
    const token = {
        nonce,
        expires: expirationDate,
    }

    const tokenStr = jwt.sign(token, ed.etc.bytesToHex(ed.utils.randomPrivateKey()));
    STORAGE.challenges[tokenStr] = token;

    setTimeout(() => {
        delete STORAGE.challenges[token];
    }, 10 * 1000 * 60)

    Logger.m("Challenge", tokenStr, "sent to the client");
    res.status(200).send({
        challenge: tokenStr
    })
})

router.post("/register_biometrics", (req, res, next) => {
    const {publicKey, validateCode} = req.body ?? {};
    const validateCodes = STORAGE.validateCodes[USER_EMAIL] ?? [];

    Logger.m("Received request with publicKey", publicKey, validateCode ? `and validate code ${validateCode}` : 'and no validate code');

    if (!publicKey) {
        return res.status(401).send(Logger.w("No public key provided"))
    }

    if (!!STORAGE.publicKeys[USER_EMAIL]?.includes(publicKey)) {
        return res.status(401).send(Logger.w("Public key is already registered"));
    }

    if (!validateCode && STORAGE.publicKeys[USER_EMAIL]?.length > 0) {
        return res.status(401).send(Logger.w("Validate code required"));
    }

    if (validateCode && !STORAGE.publicKeys[USER_EMAIL]?.length) {
        const isValidateCodeCorrect = validateCodes.at(-1) === validateCode;
        if (!isValidateCodeCorrect) {
            return res.status(401).send(Logger.w("Validate code invalid"));
        }

        validateCodes.pop();
    }

    STORAGE.publicKeys[USER_EMAIL] ??= [];
    STORAGE.publicKeys[USER_EMAIL].push(publicKey);

    Logger.m("Registered biometrics for public key", publicKey);
    res.status(200).send(true)

    // res.redirect("/request_biometric_challenge");
})

router.post("/authorize_transaction", (req, res) => {
    const {transactionID, signedChallenge, validateCode, otp} = req.body ?? {};
    const validateCodes = STORAGE.validateCodes[USER_EMAIL] ?? [];

    if (!transactionID) {
        return res.status(401).send(Logger.w("No transaction ID provided"))
    }

    const userPublicKeys = STORAGE.publicKeys[USER_EMAIL];

    if (!userPublicKeys || !userPublicKeys.length) {
        return res.status(401).send(Logger.w("User is not registered"));
    }

    if (signedChallenge) {
        Logger.m("Authorizing transaction", transactionID, "with signed challenge", signedChallenge);
        const authorized = userPublicKeys.some((key) => isTokenValid(signedChallenge, key));
        Logger[authorized ? "m" : "w"](authorized ? "User authorized successfully using challenge" : "Unable to authorize user using challenge");
        return res.status(authorized ? 200 : 401).send(authorized);
    }

    if (validateCode) {
        Logger.m("Authorizing transaction", transactionID, "with validate code", validateCode);
        const isValidateCodeCorrect = validateCodes.at(-1) === validateCode;
        if (isValidateCodeCorrect) {
            validateCodes.pop();
        }
        Logger[isValidateCodeCorrect ? "m" : "w"](isValidateCodeCorrect ? "User authorized successfully using validate code" : "Unable to authorize user using validate code");
        return res.status(isValidateCodeCorrect ? 200 : 401).send(isValidateCodeCorrect);
    }

    res.status(400).send(Logger.w("Bad request"));
})

router.use(function(req, res, next) {
    res.send("Error: Not Found");
});

module.exports = router;
