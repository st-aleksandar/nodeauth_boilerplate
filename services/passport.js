const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const extractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');


const localOptions = { usernameField: 'email' };

// Create local strategy
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {
    // verify this email and password, call done with the user
    // if it is correct email and password
    // otherwise, call done with false

    User.findOne({ email: email }, (err, user) => {
        if (err) { return done(err); }

        if (!user) { return done(null, false) ;}


        // compare passwords
        user.comparePassword(password, function(err, isMatch){

            if (err) { return done(err); }

            if (!isMatch) { return done(null, false); }

            return done(null, user);
        })

    });

});

// Setup options for JWT strategy
const jwtOptions = {
    jwtFromRequest: extractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {

    // See if the user ID in the payload exists in our database
    // if it does, call 'done' with that other
    // otherwise, call done without a user object
    User.findById(payload.sub, (err, user) => {
        if (err) { return done(err, false); }


        if (user) {
            done(null, user);
        } else {
            done(null, false);
        }

    });

});

// tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
