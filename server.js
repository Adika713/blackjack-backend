const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const session = require('express-session');
const MongoStore = require('connect-mongo');
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: 'https://blackjack-frontend-lilac.vercel.app',
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions'
  }),
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Debug session middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] Session ID: ${req.sessionID}`);
  console.log(`[${new Date().toISOString()}] User: ${req.user ? req.user.username : 'None'}`);
  console.log(`[${new Date().toISOString()}] Authenticated: ${req.isAuthenticated()}`);
  next();
});

// MongoDB connection
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  discordId: { type: String, required: true, unique: true },
  username: { type: String, required: true },
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
    let user = await User.findOne({ discordId: profile.id });
    if (!user) {
      user = new User({
        discordId: profile.id,
        username: profile.username,
        avatar: profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null
      });
      await user.save();
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Routes
app.get('/', (req, res) => {
  res.send('Blackjack Backend Running');
});

// Check Authentication
app.get('/check-auth', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ authenticated: true, user: req.user.username });
  } else {
    res.json({ authenticated: false });
  }
});

// Discord Auth
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', {
  failureRedirect: 'https://blackjack-frontend-lilac.vercel.app'
}), (req, res) => {
  console.log(`[${new Date().toISOString()}] Callback: User authenticated: ${req.user.username}`);
  res.redirect('https://blackjack-frontend-lilac.vercel.app/?page=profil');
});

// User Info
app.get('/profile', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      discordId: req.user.discordId,
      username: req.user.username,
      avatar: req.user.avatar,
      chips: req.user.chips,
      gamesPlayed: req.user.gamesPlayed,
      wins: req.user.wins,
      losses: req.user.losses,
      totalBets: req.user.totalBets
    });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
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
app.get('/balance', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ chips: req.user.chips });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Blackjack Game
app.post('/game/bet', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Not authenticated' });
  const { bet } = req.body;
  if (!bet || bet <= 0 || bet > req.user.chips) {
    return res.status(400).json({ error: 'Invalid bet' });
  }
  try {
    req.user.chips -= bet;
    req.user.gamesPlayed += 1;
    req.user.totalBets += bet;
    await req.user.save();
    res.json({ chips: req.user.chips, bet });
  } catch (err) {
    console.error('Error placing bet:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update game result
app.post('/game/result', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Not authenticated' });
  const { won, chipsWon } = req.body;
  try {
    if (won) {
      req.user.wins += 1;
      req.user.chips += chipsWon;
    } else {
      req.user.losses += 1;
    }
    await req.user.save();
    res.json({ chips: req.user.chips });
  } catch (err) {
    console.error('Error updating game result:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});