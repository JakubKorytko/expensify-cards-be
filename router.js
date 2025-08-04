const ed = require('@noble/ed25519');
const express = require('express');
const router = express.Router();

const storage = {
    key: undefined
}

router.post('/key', function(req, res, next) {
    if (storage.key) {
        res.status(401).send("Key error");
        return;
    }

    const {key} = req.body;

    if (!key) {
        res.status(401).send("Key error");
        return;
    }

    storage.key = key;
    res.send("OK");
});

router.get('/key', function(req, res, next) {
    res.json({
        key: storage.key
    })
})

router.delete('/key', function(req, res, next) {
    storage.key = undefined;
})

router.get('/token', function(req, res, next) {
    const token = ed.etc.randomBytes(8);

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

    if (!token || !signature || !storage.key) {
        res.send(false);
        return;
    }

    res.send(await ed.verifyAsync(signature, token, storage.key));
});

router.use(function(req, res, next) {
    res.send("Error: Not Found");
});

module.exports = router;
