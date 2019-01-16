const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');


function tokenForUser(user) {
    const timestemp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timestemp }, config.secret);
}


exports.signup = (req, res, next) => {

    const email = req.body.email;
    const password = req.body.password;

    if (!email || !password) {
        return res.status(402).send({error: 'You must provide an email and a password!'});
    }

    // see if a user with given email exists
    User.findOne({email: email}, (err, existingUser) => {
        if (err) {return next(err);}

        // if a user with email does exist, return an error
        if (existingUser) {
            return res.status(422).send({error: 'Email is in use'});
        }

        // if a user with email does NOT exist, create and save user record
        const user = new User({
            email: email,
            password: password
        });

        user.save( err =>  {
            if (err) {return next(err);}

            // Respond to request indicating the user was created
            res.json({token: tokenForUser(user)});

        });

    });

};


exports.signin = (req, res, next) => {
    res.send({token: tokenForUser(req.user)});
};
