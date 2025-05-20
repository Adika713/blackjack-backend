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

console.log('Starting Blackjack backend server...');

mongoose.set('strictQuery', true);

app.use(cors({
  origin: 'https://blackjack-frontend-lilac.vercel.app',
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

app.options('*', cors(), (req, res) => {
  console.log('Handling OPTIONS request:', req.path);
  res.setHeader('Access-Control-Allow-Origin', 'https://blackjack-frontend-lilac.vercel.app');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie');
  res.status(204).send();
});

app.use((req, res, next) => {
  console.log('Request:', {
    path: req.path,
    method: req.method,
    headers: req.headers,
    cookies: req.cookies,
    body: req.body,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
  res.setHeader('Access-Control-Allow-Origin', 'https://blackjack-frontend-lilac.vercel.app');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

app.use(express.json());
app.use(cookieParser());

const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET', 'DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error('Missing environment variables:', missingEnvVars.join(', '));
  process.exit(1);
}

const mongoUri = process.env.MONGO_URI;
async function connectToMongoDB(attempt = 1, maxAttempts = 10) {
  try {
    console.log(`Attempting MongoDB connection (Attempt ${attempt}/${maxAttempts})...`);
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000
    });
    console.log('Connected to MongoDB, Database:', mongoose.connection.db.databaseName);

    const indexes = await User.collection.getIndexes();
    if (indexes.username_1 && !indexes.username_1.collation) {
      console.log('Dropping conflicting username_1 index...');
      await User.collection.dropIndex('username_1');
    }
    if (indexes.email_1 && !indexes.email_1.collation) {
      console.log('Dropping conflicting email_1 index...');
      await User.collection.dropIndex('email_1');
    }

    await User.createIndexes();
    console.log('User indexes created');
  } catch (err) {
    console.error(`MongoDB connection attempt ${attempt} failed:`, err.message, err.stack);
    if (attempt < maxAttempts) {
      const delay = attempt * 5000;
      console.log(`Retrying MongoDB connection in ${delay/1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return connectToMongoDB(attempt + 1, maxAttempts);
    }
    console.error('Max MongoDB connection attempts reached. Server will continue with limited functionality.');
  }
}

connectToMongoDB();

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

userSchema.index({ username: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
userSchema.index({ email: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
userSchema.index({ discordId: 1 }, { unique: true, sparse: true });

userSchema.pre('save', function(next) {
  if (this.username) this.username = this.username.toLowerCase();
  if (this.email) this.email = this.email.toLowerCase();
  next();
});

const User = mongoose.model('User', userSchema);

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: 'https://blackjack-backend-aew7.onrender.com/auth/discord/callback',
  scope: ['identify']
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

const authenticateJWT = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    console.log('No JWT token found for path:', req.path, 'Cookies:', req.cookies);
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      console.log('User not found for ID:', decoded.userId);
      return res.status(401).json({ error: 'User not found' });
    }
    req.jwtUser = user;
    next();
  } catch (err) {
    console.error('JWT verification error:', req.path, err.message);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const balanceLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests to /balance'
});

app.get('/health', (req, res) => {
  const status = mongoose.connection.readyState === 1 ? 'ok' : 'db-error';
  console.log('Health check:', { status, db: mongoose.connection.readyState });
  res.json({ status, dbConnected: mongoose.connection.readyState === 1 });
});

app.get('/', (req, res) => {
  console.log('Root endpoint accessed');
  res.send('Blackjack Backend Running');
});

app.post('/register', async (req, res) => {
  let { username, email, password } = req.body;
  console.log('Register attempt:', { username, email, headers: req.headers });

  try {
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
      return res.status(400).json({ error: 'Password must be 8+ characters with 1 letter and 1 number' });
    }

    username = username.toLowerCase();
    email = email.toLowerCase();
    console.log('Normalized inputs:', { username, email });

    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected');
      return res.status(500).json({ error: 'Database connection error' });
    }

    const usernameExists = await User.findOne({ username }).collation({ locale: 'en', strength: 2 });
    if (usernameExists) {
      console.log('Username exists:', username, 'Found:', usernameExists);
      return res.status(400).json({ error: 'Username already exists' });
    }

    const emailExists = await User.findOne({ email }).collation({ locale: 'en', strength: 2 });
    if (emailExists) {
      console.log('Email exists:', email, 'Found:', emailExists);
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Creating user:', username);

    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    console.log('User registered, setting token for:', username);

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/'
    });
    console.log('Set-Cookie header sent for:', username, 'Token:', token.slice(0, 10) + '...');
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

app.post('/login', async (req, res) => {
  let { email, password } = req.body;
  console.log('Login attempt:', { email });
  try {
    email = email.toLowerCase();
    const user = await User.findOne({ email }).collation({ locale: 'en', strength: 2 });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log('Invalid email or password:', { email });
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    console.log('User logged in, setting token for:', user.username);
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/'
    });
    console.log('Set-Cookie header sent for:', user.username, 'Token:', token.slice(0, 10) + '...');
    res.json({ message: 'Logged in', user: { username: user.username, email, chips: user.chips } });
  } catch (err) {
    console.error('Login error:', err.message, err.stack);
    res.status(500).json({ error: 'Server error' });
  }
});

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

app.get('/auth/discord', authenticateJWT, (req, res, next) => {
  console.log('Initiating Discord auth for user:', req.jwtUser.username);
  const state = crypto.randomBytes(16).toString('hex');
  const token = req.cookies.token;
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

app.get('/balance', balanceLimiter, authenticateJWT, (req, res) => {
  console.log('Balance accessed for user:', req.jwtUser.username);
  res.json({ chips: req.jwtUser.chips });
});

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

app.use((err, req, res, next) => {
  console.error('Server error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    timestamp: new Date().toISOString()
  });
  res.setHeader('Access-Control-Allow-Origin', 'https://blackjack-frontend-lilac.vercel.app');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.status(500).json({ error: 'Server error' });
});

setInterval(() => {
  console.log('Keep-alive ping:', new Date().toISOString());
}, 5 * 60 * 1000);

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});