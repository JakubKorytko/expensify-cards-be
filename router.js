const express = require('express');
const router = express.Router();

router.get('/key', function(req, res, next) {
    res.send('respond with a resource');
});

router.get('/token', function(req, res, next) {
    res.send('respond with a resource');
});

router.get('/verify', function(req, res, next) {
    res.send('respond with a resource');
});

router.use(function(req, res, next) {
    res.send("Error: Not Found");
});

module.exports = router;
