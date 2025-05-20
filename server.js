const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const winston = require('winston');
const app = express();
const port = process.env.PORT || 3000;

// Configure Winston logger
const logger = winston.createLogger({
  level: 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'discord-jwt-callback.log' }),
    new winston.transports.Console()
  ]
});

// Set Mongoose strictQuery to suppress deprecation warning
mongoose.set('strictQuery', true);

// Middleware
app.use(cors({
  origin: 'https://blackjack-frontend-lilac.vercel.app',
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(cookieParser());

// Log incoming cookies and headers for debugging
app.use((req, res, next) => {
  logger.debug('Request received', {
    path: req.path,
    cookies: req.cookies,
    headers: req.headers
  });
  next();
});

// MongoDB connection
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error('MongoDB connection error', { error: err.message }));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, match: /^[a-zA-Z0-9_]{3,20}$/ },
  email: { type: String, required: true, unique: true, match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
  password: { type: String, required: true },
  discordId: { type: String, unique: true, sparse: true },
  avatar: String,
  chips: { type: Number, default: 1000 },
  gamesPlayed: { type: Number, default: 0 },
  wins: { type: Number, default: 0 },
  losses: { type: Number, default: 0 },
  totalBets: { type: Number, default: 0 }
});

const User = mongoose.model('User', userSchema);

// Passport Discord Strategy
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: 'https://blackjack-backend-aew7.onrender.com/auth/discord/callback',
  scope: ['identify']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    logger.info('Discord strategy processing', { discordId: profile.id, accessToken });
    return done(null, profile);
  } catch (err) {
    logger.error('Discord strategy error', { error: err.message, stack: err.stack });
    return done(err, null);
  }
}));

// Initialize Passport without session
app.use(passport.initialize());

// JWT Middleware
const authenticateJWT = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    logger.warn('No JWT token found in cookies', { path: req.path });
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    if (!process.env.JWT_SECRET) {
      logger.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      logger.warn('User not found for ID', { userId: decoded.userId });
      return res.status(401).json({ error: 'User not found' });
    }
    req.jwtUser = user;
    next();
  } catch (err) {
    logger.error('JWT verification error', { path: req.path, error: err.message });
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Rate limit for /balance
const balanceLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests to /balance, please try again later'
});

// Routes
app.get('/', (req, res) => {
  logger.info('Root endpoint accessed');
  res.send('Blackjack Backend Running');
});

// Register
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  if (!password || !/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(password)) {
    return res.status(400).json({ error: 'Password must be 8+ characters with at least 1 letter and 1 number' });
  }
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    if (!process.env.JWT_SECRET) {
      logger.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 });
    res.json({ message: 'Registered and logged in', user: { username, email, chips: user.chips } });
  } catch (err) {
    logger.error('Register error', { error: err.message });
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    if (!process.env.JWT_SECRET) {
      logger.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 });
    res.json({ message: 'Logged in', user: { username: user.username, email, chips: user.chips } });
  } catch (err) {
    logger.error('Login error', { error: err.message });
    res.status(500).json({ error: 'Server error' });
  }
});

// Check Authentication
app.get('/check-auth', authenticateJWT, (req, res) => {
  res.json({
    authenticated: true,
    user: {
      username: req.jwtUser.username,
      email: req.jwtUser.email,
      discordConnected: !!req.jwtUser.discordId
    }
  });
});

// Connect Discord
app.get('/auth/discord', authenticateJWT, (req, res, next) => {
  const state = crypto.randomBytes(16).toString('hex');
  const tempPayload = {
    userId: req.jwtUser._id.toString(),
    state
  };
  const tempToken = jwt.sign(tempPayload, process.env.JWT_SECRET, { expiresIn: '10m' });
  logger.info('Initiating Discord auth', { username: req.jwtUser.username, userId: req.jwtUser._id, state });
  passport.authenticate('discord', {
    state: tempToken, // Pass temp JWT as state
    session: false
  })(req, res, next);
});

// Discord Callback
app.get('/auth/discord/callback', (req, res, next) => {
  logger.debug('Discord callback received', { query: req.query });
  passport.authenticate('discord', { session: false }, async (err, profile, info) => {
    if (err) {
      logger.error('Passport authentication error', { error: err.message, stack: err.stack });
      return res.redirect('https://blackjack-frontend-lilac.vercel.app/?error=auth_error');
    }
    if (!profile) {
      logger.warn('Passport authentication failed', { info, query: req.query });
      return res.redirect('https://blackjack-frontend-lilac.vercel.app/?error=no_profile');
    }
    try {
      const tempToken = req.query.state;
      if (!tempToken) {
        logger.warn('No state parameter in callback', { query: req.query });
        return res.redirect('https://blackjack-frontend-lilac.vercel.app/?error=invalid_state');
      }
      let tempPayload;
      try {
        tempPayload = jwt.verify(tempToken, process.env.JWT_SECRET);
      } catch (jwtErr) {
        logger.error('Invalid state JWT', { error: jwtErr.message });
        return res.redirect('https://blackjack-frontend-lilac.vercel.app/?error=invalid_state');
      }

      const userId = tempPayload.userId;
      const dbUser = await User.findById(userId);
      if (!dbUser) {
        logger.warn('User not found for ID', { userId });
        return res.redirect('https://blackjack-frontend-lilac.vercel.app/?error=user_not_found');
      }

      const discordId = profile.id;
      const existingUser = await User.findOne({ discordId });
      if (existingUser && existingUser._id.toString() !== dbUser._id.toString()) {
        logger.warn('Discord account already linked', { discordId, userId: dbUser._id });
        return res.redirect('https://blackjack-frontend-lilac.vercel.app/?error=discord_linked');
      }

      dbUser.discordId = discordId;
      dbUser.avatar = dbUser.avatar || `https://cdn.discordapp.com/avatars/${discordId}/${profile.avatar}.png`;
      await dbUser.save();
      logger.info('Discord connected', { username: dbUser.username, discordId });

      // Generate new JWT with updated user data
      const newToken = jwt.sign(
        { userId: dbUser._id, discordId: dbUser.discordId },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      logger.info('New JWT generated', { userId: dbUser._id, discordId });

      res.cookie('token', newToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 24 * 60 * 60 * 1000
      });
      res.redirect('https://blackjack-frontend-lilac.vercel.app/?page=profil');
    } catch (err) {
      logger.error('Discord callback error', { error: err.message, stack: err.stack });
      res.redirect('https://blackjack-frontend-lilac.vercel.app/?error=server_error');
    }
  })(req, res, next);
});

// User Info
app.get('/profile', authenticateJWT, (req, res) => {
  res.json({
    username: req.jwtUser.username,
    email: req.jwtUser.email,
    avatar: req.jwtUser.avatar,
    chips: req.jwtUser.chips,
    gamesPlayed: req.jwtUser.gamesPlayed,
    wins: req.jwtUser.wins,
    losses: req.jwtUser.losses,
    totalBets: req.jwtUser.totalBets,
    discordConnected: !!req.jwtUser.discordId
  });
});

// Leaderboard
app.get('/leaderboard', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 20;
    const skip = (page - 1) * limit;
    const users = await User.find()
      .sort({ chips: -1 })
      .skip(skip)
      .limit(limit)
      .select('username chips gamesPlayed');
    const total = await User.countDocuments();
    res.json({ users, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    logger.error('Error fetching leaderboard', { error: err.message });
    res.status(500).json({ error: 'Server error' });
  }
});

// Balance
app.get('/balance', balanceLimiter, authenticateJWT, (req, res) => {
  res.json({ chips: req.jwtUser.chips });
});

// Blackjack Game
app.post('/game/bet', authenticateJWT, async (req, res) => {
  if (!req.jwtUser.discordId) return res.status(403).json({ error: 'Connect Discord to play' });
  const { bet } = req.body;
  if (!bet || bet <= 0 || bet > req.jwtUser.chips) {
    return res.status(400).json({ error: 'Invalid bet' });
  }
  try {
    req.jwtUser.chips -= bet;
    req.jwtUser.gamesPlayed += 1;
    req.jwtUser.totalBets += bet;
    await req.jwtUser.save();
    res.json({ chips: req.jwtUser.chips, bet });
  } catch (err) {
    logger.error('Error placing bet', { error: err.message });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update game result
app.post('/game/result', authenticateJWT, async (req, res) => {
  if (!req.jwtUser.discordId) return res.status(403).json({ error: 'Connect Discord to play' });
  const { won, chipsWon } = req.body;
  try {
    if (won) {
      req.jwtUser.wins += 1;
      req.jwtUser.chips += chipsWon;
    } else {
      req.jwtUser.losses += 1;
    }
    await req.jwtUser.save();
    res.json({ chips: req.jwtUser.chips });
  } catch (err) {
    logger.error('Error updating game result', { error: err.message });
    res.status(500).json({ error: 'Server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Server error', { path: req.path, error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
  logger.info(`Server running on port ${port}`);
});