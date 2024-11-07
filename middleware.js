const passport = require('passport');
const jwt = require('jsonwebtoken'); 
// Middleware function for handling local login
const loginMiddleware = (req, res, next) => {
    passport.authenticate('local', (err, data, info) => {
        if (err) {
            return res.status(500).json({ message: 'Error logging in' });
        }
        if (!data) {
            return res.status(400).json(info);
        }

        const { token, user } = data;
        res.json({ token, user });
    })(req, res, next); // Executes the middleware with the provided req, res, and next
};
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Expects 'Bearer <token>'

    if (!token) return res.status(401).json({ message: 'Access token is missing' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("SUCESFULLY DECODED",decoded)
        req.user = decoded; // Set the decoded user info on `req.user`
        next();
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
};

module.exports = {authenticateJWT,
    loginMiddleware,
};