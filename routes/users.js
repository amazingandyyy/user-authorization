var express = require('express');
var router = express.Router();

var User = require('../models/user')

router.get('/', (err, res) => {
    User.find({}, (err, users) => {
        res.status(err ? 400 : 200).send(err || users);
    });
})
router.post('/register', (req, res) => {
    User.register(req.body, (err, savedUser) => {
        res.status(err ? 400 : 200).send(err || savedUser);
    })
})
router.post('/authenticate', (req, res) => {
    User.authenticate(req.body, (err, token) => {
        if (err) {
            res.status(400).send(err);
        } else {
            res.cookie('accessToken: ', token).send();
        }
    })
})
router.post('/logout', (req, res) => {
    res.clearCookie('accessToken').send();
});

module.exports = router;
