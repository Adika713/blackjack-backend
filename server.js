const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
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

// Log incoming cookies and headers for debugging
app.use((req, res, next) => {
  console.log('Request path:', req.path, 'Cookies:', req.cookies, 'Headers:', req.headers, 'Session ID:', req.sessionID);
  next();
});

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'session-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60,
    autoRemove: 'native'
  }, err => {
    if (err) console.error('MongoStore initialization error:', err);
  }),
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
  scope: ['identify'],
  state: true
}, async (accessToken, refreshToken, profile, done) => {
  try {
    console.log('Discord strategy processing for user:', profile.id);
    return done(null, profile);
  } catch (err) {
    console.error('Discord strategy error:', err.message, err.stack);
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  console.log('Serializing user:', user.id);
  done(null, user);
});
passport.deserializeUser((user, done) => {
  console.log('Deserializing user:', user.id);
  done(null, user);
});

// JWT Middleware
const authenticateJWT = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    console.log('No JWT token found in cookies for path:', req.path, 'Session ID:', req.sessionID);
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      console.log('User not found for ID:', decoded.userId, 'Session ID:', req.sessionID);
      return res.status(401).json({ error: 'User not found' });
    }
    req.jwtUser = user;
    next();
  } catch (err) {
    console.error('JWT verification error for path:', req.path, 'Error:', err.message, 'Session ID:', req.sessionID);
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
  console.log('Root endpoint accessed, Session ID:', req.sessionID);
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
      console.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
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
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
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
  console.log('Initiating Discord auth for user:', req.jwtUser.username, 'Setting jwtUserId:', req.jwtUser._id, 'Session ID:', req.sessionID);
  const state = crypto.randomBytes(16).toString('hex');
  req.session.jwtUserId = req.jwtUser._id.toString();
  req.session.state = state;
  req.session.save(err => {
    if (err) {
      console.error('Session save error in /auth/discord:', err);
      return res.status(500).json({ error: 'Session error' });
    }
    console.log('Session saved with jwtUserId:', req.session.jwtUserId, 'State:', state, 'Session ID:', req.sessionID);
    passport.authenticate('discord', { state })(req, res, next);
  });
});

app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), async (req, res) => {
  try {
    console.log('Discord callback session:', req.session, 'Session ID:', req.sessionID, 'Query:', req.query);
    const receivedState = req.query.state;
    const storedState = req.session.state;
    const userId = req.session.jwtUserId;
    
    if (!receivedState || receivedState !== storedState) {
      console.log('Invalid state parameter:', { receivedState, storedState }, 'Session ID:', req.sessionID);
      return res.status(401).json({ error: 'Invalid state' });
    }
    
    if (!userId) {
      console.log('No jwtUserId found in session for Session ID:', req.sessionID);
      return res.status(401).json({ error: 'User session lost' });
    }
    
    const discordId = req.user.id; // From Discord profile
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
    
    delete req.session.jwtUserId;
    delete req.session.state;
    req.session.save(err => {
      if (err) {
        console.error('Session save error in /auth/discord/callback:', err);
      }
      res.redirect('https://blackjack-frontend-lilac.vercel.app/?page=profil');
    });
  } catch (err) {
    console.error('Discord callback error:', err.message, err.stack);
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