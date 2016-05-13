var express = require('express');
var router = express.Router();

var User = require('../models/user');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});


router.get('/secret', User.auth(), function(req, res, next) {
    console.log('req.loggedinUser', req.loggedinUser);
    res.send('secret')
});
router.get('/admin', User.auth('admin'), function(req, res, next) {
    console.log('req.loggedinUser', req.loggedinUser);
    res.send('admin page');
});
// router.get('/secret', User.isLoggedIn, function(req, res, next) {
//     console.log('req.loggedinUser', req.loggedinUser);
//     res.send('secret')
// });
// router.get('/admin', User.isLoggedIn, User.isAdmin, function(req, res, next) {
//     console.log('req.loggedinUser', req.loggedinUser);
//     res.send('secret');
// });

module.exports = router;
