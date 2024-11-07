const passport = require('passport');
require('dotenv').config();
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');


const prisma = new PrismaClient();


const generateToken = (user) => {
    // Create a JWT token with user info (e.g., user ID)
    return jwt.sign({ id: user.id,
       email: user.email,
       username:user.username
     }, process.env.JWT_SECRET, { expiresIn: '1h' });
};


passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return done(null, false, { message: 'Incorrect email.' });

        const isValidPassword = await bcrypt.compare(password, user.passwordHash);
        if (!isValidPassword) return done(null, false, { message: 'Incorrect password.' });

        // Generate JWT token upon successful login
        const token = generateToken(user);
        return done(null, { user, token });
    } catch (error) {
        done(error);
    }
}));

// Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await prisma.user.findUnique({ where: { oauthProviderId: profile.id } });

        if (!user) {
            // Create new user if not found
            user = await prisma.user.create({
                data: {
                    email: profile.emails[0].value,
                    oauthProvider: 'google',
                    oauthProviderId: profile.id,
                    username:profile.displayName,
                    
                }
            });
        }
        console.log(profile)

        // Generate JWT token for new or existing user
        const token = generateToken(user);
        done(null, { user, token });
    } catch (error) {
        done(error);
    }
}));
module.exports = { passport, generateToken };