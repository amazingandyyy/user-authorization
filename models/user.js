'use strict';

var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var moment = require('moment');
var JWT_SECRET = process.env.JWT_SECRET;

var userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },

    password: {
        type: String,
        required: true
    },

    admin: {
        type: Boolean,
        default: false
    }
});


// Model methods
// User.register - create a new user, hash their password
// User. authenticate - log in a user, and give them a token


// Middleware
// User.isLoggedIn - verify user is authenticated
// User.isAdmin - verify user is admin


// Instance methods
// user.generateToken - generate a JWT token
// user.makeAdmin


userSchema.statics.register = (userObj, cb) => {
    // 'this' is model User
    User.findOne({
        email: userObj.email
    }, (err, dbUser) => {
        if (err || dbUser) return cb(err || {
            err: 'Email has been taken'
        });
        bcrypt.hash(userObj.password, 12, (err, hash) => {
            if (err) return cb(err);

            var user = new User({
                email: userObj.email,
                password: hash
            })

            user.save((err, savedUser) => {
                savedUser.password = null;
                cb(err, savedUser);
            });
        });
    });
};

userSchema.statics.authenticate = (userObj, cb) => {
    User.findOne({
        email: userObj.email
    }, (err, dbUser) => {
        if (err || !dbUser) return cb(err || {
            error: 'Authentication Failed. Invalid email or password.'
        });

        bcrypt.compare(userObj.password, dbUser.password, (err, success) => {
            if (err || !success) return cb(err || {
                error: 'Authentication Failed. Invalid email or password.'
            })
            console.log('dbUser: ', dbUser);
            var token = dbUser.generateToken();
            cb(null, token);
        });
    });
};

userSchema.statics.auth = (role) => {
    return (req, res, next) => {

        var token = req.cookies.accessToken;
        console.log('token: ', token);
        jwt.verify(token, JWT_SECRET, (err, payload) => {
            console.log('payload: ', payload);
            if (err) return res.status(401).send({
                errer: 'Authentication failed.'
            });

            var userId = payload._id;
            User.findById(userId, (err, user) => {
                if (err || !user) return res.status(401).send({
                    error: 'User not found'
                })
                req.loggedinUser = user;
                    if (role==='admin' && !req.loggedinUser.admin) {
                        // if the role is admin and but has admin as false
                        res.status(403).send({error: 'you are fake admin.'});
                    }
                    // for normal or admin user to go
                    next()
            }).select('-password');
        });
    }
}

// userSchema.statics.isLoggedIn = (req, res, next) => {
//     var token = req.cookies.accessToken;
//     console.log('token: ', token);
//     jwt.verify(token, JWT_SECRET, (err, payload) => {
//         console.log('payload: ', payload);
//         if (err) return res.status(401).send({
//             errer: 'Authentication failed.'
//         });
//
//         var userId = payload._id;
//         User.findById(userId, (err, user) => {
//             if (err || !user) return res.status(401).send({
//                 error: 'User not found'
//             })
//             req.loggedinUser = user;
//             next();
//         }).select('-password');
//     });
// };
// userSchema.statics.isAdmin = (req, res, next) => {
//     if (req.loggedinUser.admin) {
//         next()
//     } else {
//         res.status(403).send({
//             error: 'Not authrized.'
//         });
//     }
// };

userSchema.methods.generateToken = function() {
    console.log('this: ', this);
    console.log('id: ', this._id);
    var payload = {
        _id: this._id,
        exp: moment().add(1, 'day').unix()
    };
    return jwt.sign(payload, JWT_SECRET);
}



var User = mongoose.model('User', userSchema);
module.exports = User;
