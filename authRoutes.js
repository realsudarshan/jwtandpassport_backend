const express = require('express');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const { generateToken } = require('./passport-auth.js');
const { loginMiddleware,authenticateJWT } = require('./middleware.js');

const prisma = new PrismaClient();
const router = express.Router();

router.post('/signup', async (req, res) => {
    const { email, password, username } = req.body;
    try {
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ message: 'User already exists.' });

        const passwordHash = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: { email, passwordHash, username },
        });

        const token = generateToken(user);
        res.json({ token, user });
    } catch (error) {
        res.status(500).json({ message: 'Error signing up' });
    }
});

router.post('/login', loginMiddleware);
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    const { user, token } = req.user;
    res.redirect(`${process.env.CLIENT_URL}/auth/success?token=${token}`);
});
router.get('/profile', authenticateJWT, (req, res) => {
    // You can replace the hardcoded profile with actual data from your database
    res.json({
      displayName: req.user.username,
      email: req.user.email,
    });
  });
module.exports = router;
