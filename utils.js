const ed = require('@noble/ed25519');

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
    e: (...args) => {
        if (DISABLE_LOGGER) return;
        console.error("[ERROR]", ...args, "\n");
        return args.join(" ");
    },
    w: (...args) =>
    {
        if (DISABLE_LOGGER) return;
        console.warn("[WARN]", ...args, "\n");
        return args.join(" ");
    },
    m: (...args) =>
    {
        if (DISABLE_LOGGER) return;
        console.log("[INFO]", ...args, "\n")
        return args.join(" ");
    },
};

function generateSixDigitNumber() {
    return Math.floor(Math.random() * 900000) + 100000;
}

const getOriginalChallengeJWT = (signature, key) => {
    const challengeKeys = Object.keys(STORAGE.challenges);

    const challengeJWT = challengeKeys.find(challengeKey => {
        Logger.m("Verifying signature", signature, "for nonce", challengeKey, "with key", key);
        let verifyResult;
        try {
            verifyResult = ed.verify(signature, new TextEncoder().encode(challengeKey), key);
        } catch (e) {
            Logger.e(e);
        }
        Logger.m("Verification for signature", signature, "result:", verifyResult ? "success" : "failed");
        return verifyResult;
    })
    if (!challengeJWT) {
        return null;
    }

    return challengeJWT;
}

const isChallengeValid = function (signedJWTString, publicKey) {
    try {
        const challengeJWT = getOriginalChallengeJWT(signedJWTString, publicKey) ?? {};

        if (!challengeJWT) {
            return false;
        }

        const {nonce, expires} = STORAGE.challenges[challengeJWT];

        if (!nonce || !expires) {
            return false;
        }

        delete STORAGE.challenges[challengeJWT];
        const challengeExpired = expires < Date.now();

        if (challengeExpired) {
            Logger.m(`Challenge ${challengeJWT} expired, removed from storage`)
        } else {
            Logger.m(`Challenge ${challengeJWT} success, removed from storage`)
        }

        return !challengeExpired;
    } catch (e) {
        return false;
    }
}

module.exports = {
    isChallengeValid,
    generateSixDigitNumber,
    STORAGE,
    USER_EMAIL,
    Logger,
    ed
}