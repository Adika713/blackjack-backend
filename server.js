const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: function (origin, callback) {
    console.log('Environment Variables - FRONTEND_URL:', process.env.FRONTEND_URL);

    // List of allowed origins
    const allowedOrigins = [
      process.env.FRONTEND_URL || 'https://blackjack-frontend-d6umc6k0h-adika713s-projects.vercel.app',
      'https://blackjack-frontend-lilac.vercel.app',
      'https://blackjack-frontend-pcnermf4h-adika713s-projects.vercel.app'
      // Add other custom domains here, e.g., 'https://blackjack.example.com'
    ];

    if (!origin) {
      console.log('CORS Check - No origin provided, allowing request');
      return callback(null, allowedOrigins[0]);
    }

    const requestOrigin = origin.replace(/\/$/, '').toLowerCase();
    const isAllowed = allowedOrigins.some(allowed => allowed.replace(/\/$/, '').toLowerCase() === requestOrigin);

    console.log('CORS Check - Request Origin:', origin);
    console.log('CORS Check - Allowed Origins:', allowedOrigins);
    console.log('CORS Check - Normalized Request Origin:', requestOrigin);

    if (isAllowed) {
      console.log('CORS Check - Origin allowed');
      callback(null, origin); // Echo back the request origin
    } else {
      console.log('CORS Check - Origin not allowed');
      callback(new Error(`CORS Error: Origin ${origin} not allowed. Expected one of ${allowedOrigins.join(', ')}`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  chips: { type: Number, default: 1000 },
  gamesPlayed: { type: Number, default: 0 }
});

const User = mongoose.model('User', userSchema);

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  console.log('Authenticate token:', token ? token.slice(0, 10) + '...' : 'none', 'Cookies:', req.cookies);
  if (!token) return res.status(401).json({ error: 'User not found' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    console.log('Token verified, user:', decoded.username);
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/health', (req, res) => {
  console.log('Health check requested');
  res.json({ status: 'ok', dbConnected: mongoose.connection.readyState === 1 });
});

app.post('/register', async (req, res) => {
  console.log('Register request:', req.body);
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000
    });

    console.log('Set-Cookie header sent for:', user.username, 'Token:', token.slice(0, 10) + '...');
    res.json({ message: 'Registered and logged in', user: { username: user.username, email: user.email }, token });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  console.log('Login request:', { email: req.body.email });
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });

    console.log('Set-Cookie header sent for:', user.username, 'Token:', token.slice(0, 10) + '...');
    res.json({ message: 'Logged in', user: { username: user.username, email: user.email }, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/check-auth', authenticateToken, async (req, res) => {
  console.log('Check-auth requested for user:', req.user.username);
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ authenticated: true, user: { username: user.username, email: user.email } });
  } catch (err) {
    console.error('Check-auth error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

console.log('Registering /balance route');
app.get('/balance', authenticateToken, async (req, res) => {
  console.log('Balance requested for user:', req.user.username);
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ chips: user.chips });
  } catch (err) {
    console.error('Balance error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/game/bet', authenticateToken, async (req, res) => {
  console.log('Bet requested:', req.body, 'User:', req.user.username);
  const { bet } = req.body;
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (bet <= 0 || bet > user.chips) {
      return res.status(400).json({ error: 'Invalid bet amount' });
    }
    user.chips -= bet;
    await user.save();
    res.json({ chips: user.chips });
  } catch (err) {
    console.error('Bet error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/game/result', authenticateToken, async (req, res) => {
  console.log('Game result requested:', req.body, 'User:', req.user.username);
  const { won, chipsWon } = req.body;
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (won) {
      user.chips += chipsWon;
    }
    user.gamesPlayed += 1;
    await user.save();
    res.json({ chips: user.chips });
  } catch (err) {
    console.error('Game result error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});