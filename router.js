const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const {generateSixDigitNumber, STORAGE, Logger, ed, USER_EMAIL, isChallengeValid} = require("./utils");


router.post("/resend_validate_code", (req, res) => {
    Logger.m("Generating new validation code")

    const {email} = req.body ?? {};
    if (!email) {
        return res.status(401).send()
    }

    const randomCode = generateSixDigitNumber();

    STORAGE.validateCodes[email] ??= [];
    STORAGE.validateCodes[email].push(randomCode);

    Logger.m("Generated new validation code:", randomCode, "for email", email);

    res.status(200).send()
})

router.get("/request_biometric_challenge", (req, res) => {
    Logger.m("Requested biometric challenge");

    if (!STORAGE.publicKeys[USER_EMAIL]) {
        return res.status(401).send(Logger.w("Registration required"))
    }

    const nonce = ed.etc.bytesToHex(ed.etc.randomBytes(16));
    const expirationDate = Date.now() + 10 * 1000 * 60; // 10 minutes

    const challenge = {
        nonce,
        expires: expirationDate,
    }

    const challengeJWT = jwt.sign(challenge, ed.etc.bytesToHex(ed.utils.randomPrivateKey()));
    STORAGE.challenges[challengeJWT] = challenge;

    setTimeout(() => {
        Logger.m(`Challenge ${challengeJWT} expired, removed from storage`)
        delete STORAGE.challenges[challengeJWT];
    }, 10 * 1000 * 60)

    Logger.m("Challenge", challengeJWT, "sent to the client");

    res.status(200).send({
        challenge: challengeJWT
    })
})

router.post("/register_biometrics", (req, res) => {
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
    const {transactionID, signedChallenge, validateCode} = req.body ?? {};
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

        const authorized = userPublicKeys.some((publicKey) => isChallengeValid(signedChallenge, publicKey));
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

router.use(function(req, res) {
    res.send("Error: Not Found");
});

module.exports = router;
