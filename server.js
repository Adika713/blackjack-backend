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
  console.log('Request path:', req.path, 'Cookies:', req.cookies, 'Headers:', req.headers);
  next();
});

// MongoDB connection with retry
const mongoUri = process.env.MONGO_URI;
if (!mongoUri) {
  console.error('MONGO_URI environment variable is not set');
  process.exit(1);
}

async function connectToMongoDB(attempt = 1, maxAttempts = 5) {
  try {
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB, Database:', mongoose.connection.db.databaseName);
    // Drop and recreate indexes
    await User.collection.dropIndexes().catch(err => console.warn('No indexes to drop:', err.message));
    await User.createIndexes();
    console.log('User indexes created');
  } catch (err) {
    console.error(`MongoDB connection attempt ${attempt} failed:`, err.message, err.stack);
    if (attempt < maxAttempts) {
      console.log(`Retrying MongoDB connection in ${attempt * 2} seconds...`);
      await new Promise(resolve => setTimeout(resolve, attempt * 2000));
      return connectToMongoDB(attempt + 1, maxAttempts);
    }
    console.error('Max MongoDB connection attempts reached. Exiting.');
    process.exit(1);
  }
}

connectToMongoDB();

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

// Explicitly define indexes with case-insensitive collation
userSchema.index({ username: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
userSchema.index({ email: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
userSchema.index({ discordId: 1 }, { unique: true, sparse: true });

// Normalize username and email to lowercase before saving
userSchema.pre('save', function(next) {
  if (this.username) this.username = this.username.toLowerCase();
  if (this.email) this.email = this.email.toLowerCase();
  next();
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
    console.log('Discord strategy processing for user:', profile.id, 'Access Token:', accessToken);
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
    console.log('No JWT token found in cookies for path:', req.path);
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
      console.log('User not found for ID:', decoded.userId);
      return res.status(401).json({ error: 'User not found' });
    }
    req.jwtUser = user;
    next();
  } catch (err) {
    console.error('JWT verification error for path:', req.path, 'Error:', err.message);
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
  console.log('Root endpoint accessed');
  res.send('Blackjack Backend Running');
});

// Register
app.post('/register', async (req, res) => {
  let { username, email, password } = req.body;
  console.log('Register attempt:', { username, email });

  try {
    // Validate inputs
    if (!username || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      console.log('Invalid username:', username);
      return res.status(400).json({ error: 'Username must be 3-20 characters, alphanumeric' });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      console.log('Invalid email:', email);
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (!password || !/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(password)) {
      console.log('Invalid password');
      return res.status(400).json({ error: 'Password must be 8+ characters with at least 1 letter and 1 number' });
    }

    // Normalize inputs
    username = username.toLowerCase();
    email = email.toLowerCase();
    console.log('Normalized inputs:', { username, email });

    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected');
      return res.status(500).json({ error: 'Database connection error' });
    }

    // Check JWT_SECRET
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Check for existing user (case-insensitive)
    const usernameExists = await User.findOne({ username }).collation({ locale: 'en', strength: 2 });
    if (usernameExists) {
      console.log('Username already exists:', username, 'Found:', usernameExists);
      return res.status(400).json({ error: 'Username already exists' });
    }

    const emailExists = await User.findOne({ email }).collation({ locale: 'en', strength: 2 });
    if (emailExists) {
      console.log('Email already exists:', email, 'Found:', emailExists);
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10).catch(err => {
      throw new Error(`Password hashing failed: ${err.message}`);
    });
    console.log('Creating user:', username);

    // Create and save user
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    console.log('User registered, setting token for:', username);

    // Set cookie and respond
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({
      message: 'Registered and logged in',
      user: { username, email, chips: user.chips }
    });
  } catch (err) {
    console.error('Register error:', {
      message: err.message,
      stack: err.stack,
      code: err.code,
      name: err.name,
      keyPattern: err.keyPattern,
      keyValue: err.keyValue
    });
    if (err.name === 'MongoServerError' && err.code === 11000) {
      const field = err.keyPattern ? Object.keys(err.keyPattern)[0] : 'unknown';
      console.log('Duplicate key error:', { field, value: err.keyValue });
      return res.status(400).json({ error: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists` });
    }
    if (err.name === 'ValidationError') {
      return res.status(400).json({ error: `Invalid user data: ${err.message}` });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  let { email, password } = req.body;
  console.log('Login attempt:', { email });
  try {
    // Normalize email
    email = email.toLowerCase();
    const user = await User.findOne({ email }).collation({ locale: 'en', strength: 2 });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log('Invalid email or password:', { email });
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    console.log('User logged in, setting token for:', user.username);
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 });
    res.json({ message: 'Logged in', user: { username: user.username, email, chips: user.chips } });
  } catch (err) {
    console.error('Login error:', err.message, err.stack);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check Authentication
app.get('/check-auth', authenticateJWT, (req, res) => {
  console.log('Check-auth for user:', req.jwtUser.username);
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
  console.log('Initiating Discord auth for user:', req.jwtUser.username);
  const state = crypto.randomBytes(16).toString('hex');
  const token = req.cookies.token; // Pass JWT via query to callback
  console.log('Discord auth, state:', state, 'User ID:', req.jwtUser._id);
  passport.authenticate('discord', {
    state: `${state}|${token}`
  })(req, res, next);
});

app.get('/auth/discord/callback', (req, res, next) => {
  console.log('Callback received, Query:', req.query, 'Cookies:', req.cookies);
  passport.authenticate('discord', { failureRedirect: '/' }, async (err, user, info) => {
    if (err) {
      console.error('Passport authentication error:', err.message, err.stack);
      return res.status(500).json({ error: 'Authentication error' });
    }
    if (!user) {
      console.log('Passport authentication failed:', info, 'Query:', req.query);
      return res.redirect('/');
    }
    try {
      console.log('Discord callback, User:', user.id);
      const state = req.query.state || '';
      const [receivedState, token] = state.split('|');
      if (!receivedState || !token) {
        console.log('Invalid state or token in callback');
        return res.status(401).json({ error: 'Invalid state or token' });
      }
      // Verify JWT
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const dbUser = await User.findById(decoded.userId);
      if (!dbUser) {
        console.log('User not found for ID:', decoded.userId);
        return res.status(401).json({ error: 'User not found' });
      }
      const discordId = user.id;
      const existingUser = await User.findOne({ discordId });
      if (existingUser && existingUser._id.toString() !== dbUser._id.toString()) {
        return res.status(400).json({ error: 'Discord account already linked to another user' });
      }
      dbUser.discordId = discordId;
      dbUser.avatar = dbUser.avatar || `https://cdn.discordapp.com/avatars/${discordId}/${user.avatar}.png`;
      await dbUser.save();
      console.log(`Discord connected for user: ${dbUser.username}, discordId: ${discordId}`);
      res.redirect('https://blackjack-frontend-lilac.vercel.app/?page=profil');
    } catch (err) {
      console.error('Discord callback error:', err.message, err.stack);
      res.status(500).json({ error: 'Server error' });
    }
  })(req, res, next);
});

// User Info
app.get('/profile', authenticateJWT, (req, res) => {
  console.log('Profile accessed for user:', req.jwtUser.username);
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
    console.error('Leaderboard error:', err.message, err.stack);
    res.status(500).json({ error: 'Server error' });
  }
});

// Balance
app.get('/balance', balanceLimiter, authenticateJWT, (req, res) => {
  console.log('Balance accessed for user:', req.jwtUser.username);
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
    console.error('Bet error:', err.message, err.stack);
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
    console.error('Game result error:', err.message, err.stack);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});