const express = require('express');
const passport = require('passport');
const authRoutes = require('./authRoutes');
const { authenticateJWT, loginMiddleware } = require('./middleware.js');
const cors = require('cors');
require('dotenv').config();
require('./passport-auth.js');
 // Load passport configuration

const app = express();
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json());
app.use(passport.initialize());
app.use('/auth', authRoutes);



app.get('/protected', authenticateJWT, (req, res) => {
    res.json({ message: 'You are authenticated!', user: req.user });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));


