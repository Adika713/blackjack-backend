const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cookieParser = require('cookie-parser');
const session = require('express-session');
const app = express();
const port = process.env.PORT || 3000;

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
app.use(session({
  secret: process.env.SESSION_SECRET || 'session-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

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
    return done(null, profile);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// JWT Middleware
const authenticateJWT = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    console.log('No JWT token found in cookies');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'jwt-secret-key');
    const user = await User.findById(decoded.userId);
    if (!user) {
      console.log('User not found for ID:', decoded.userId);
      return res.status(401).json({ error: 'User not found' });
    }
    req.jwtUser = user; // Store JWT user separately to avoid Passport conflict
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
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
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'jwt-secret-key', { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 });
    res.json({ message: 'Registered and logged in', user: { username, email, chips: user.chips } });
  } catch (err) {
    console.error('Register error:', err);
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
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'jwt-secret-key', { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 });
    res.json({ message: 'Logged in', user: { username: user.username, email, chips: user.chips } });
  } catch (err) {
    console.error('Login error:', err);
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
  req.session.jwtUserId = req.jwtUser._id; // Store user ID in session
  passport.authenticate('discord')(req, res, next);
});

app.get('/auth/discord/callback', authenticateJWT, passport.authenticate('discord', { failureRedirect: '/' }), async (req, res) => {
  try {
    const discordId = req.user.id; // From Discord profile
    const userId = req.session.jwtUserId; // Retrieve user ID from session
    if (!userId) {
      console.log('No jwtUserId found in session');
      return res.status(401).json({ error: 'User session lost' });
    }
    const user = await User.findById(userId);
    if (!user) {
      console.log('User not found for ID:', userId);
      return res.status(401).json({ error: 'User not found' });
    }
    const existingUser = await User.findOne({ discordId });
    if (existingUser && existingUser._id.toString() !== user._id.toString()) {
      return res.status(400).json({ error: 'Discord account already linked to another user' });
    }
    user.discordId = discordId;
    user.avatar = user.avatar || `https://cdn.discordapp.com/avatars/${discordId}/${req.user.avatar}.png`;
    await user.save();
    console.log(`Discord connected for user: ${user.username}, discordId: ${discordId}`);
    delete req.session.jwtUserId; // Clean up session
    res.redirect('https://blackjack-frontend-lilac.vercel.app/?page=profil');
  } catch (err) {
    console.error('Discord connect error:', err);
    res.status(500).json({ error: 'Server error' });
  }
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
    console.error('Error fetching leaderboard:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Balance
app.get('/balance', authenticateJWT, (req, res) => {
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
    console.error('Error placing bet:', err);
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
    console.error('Error updating game result:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});