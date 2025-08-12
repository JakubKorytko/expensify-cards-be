const ed = require('@noble/ed25519');
const express = require('express');
const router = express.Router();

const storage = {
    key: undefined
}

router.post('/key', function(req, res, next) {
    if (storage.key) {
        console.log("Key already exists");
        res.status(401).send("Key exists");
        return;
    }

    const {key} = req.body;

    if (!key) {
        res.status(401).send("Key is not present in body");
        return;
    }

    console.log("Received key", key);

    storage.key = key;
    res.send("OK");
});

router.get('/key', function(req, res, next) {
    console.log("Client requested key", storage.key);
    res.json({
        key: storage.key
    })
})

router.delete('/key', function(req, res, next) {
    storage.key = undefined;
    console.log('Removed key');
    res.send("OK");
})

router.get('/token', function(req, res, next) {
    const token = ed.etc.randomBytes(8);

    console.log("Token generated", ed.etc.bytesToHex(token), "and sent to client")

    res.json({
        bytes: token,
        hex: ed.etc.bytesToHex(token),
    });
});

router.post('/verify', async function(req, res, next) {
    const {
        token,
        signature
    } = req.body;

    console.log("Received token", token, "with signature", signature);

    if (!token || !signature || !storage.key) {
        console.log("Invalid signature");
        res.send(false);
        return;
    }

    const verificationResult = await ed.verifyAsync(signature, token, storage.key);

    console.log("Verification result", verificationResult, "sent to client");

    res.send(verificationResult);
});

router.use(function(req, res, next) {
    res.send("Error: Not Found");
});

module.exports = router;
