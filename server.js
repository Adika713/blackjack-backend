const BACKEND_URL = 'https://blackjack-backend-aew7.onrender.com';

// Navigation
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const page = item.dataset.page;
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(page).classList.add('active');
    if (page === 'leaderboard') fetchLeaderboard(1);
    if (page === 'profil') fetchProfile();
    if (page === 'verseny') checkLoginForGame();
  });
});

// Handle query parameter
function initializePage() {
  const urlParams = new URLSearchParams(window.location.search);
  const page = urlParams.get('page') || 'verseny';
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(page).classList.add('active');
  if (page === 'leaderboard') fetchLeaderboard(1);
  if (page === 'profil') fetchProfile();
  if (page === 'verseny') checkLoginForGame();
  window.history.replaceState({}, document.title, window.location.pathname);
}

// Auth Popup
const authPopup = document.getElementById('auth-popup');
const authTitle = document.getElementById('auth-title');
const authForm = document.getElementById('auth-form');
const authSubmit = document.getElementById('auth-submit');
const authError = document.getElementById('auth-error');
const authSwitch = document.getElementById('auth-switch');
const usernameInput = document.getElementById('username');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');

function showAuthPopup(isRegister) {
  authPopup.classList.remove('hidden');
  authTitle.textContent = isRegister ? 'Register' : 'Login';
  authSubmit.textContent = isRegister ? 'Register' : 'Login';
  usernameInput.parentElement.classList.toggle('hidden', !isRegister);
  authSwitch.innerHTML = isRegister
    ? `Already have an account? <a href="#" id="switch-to-login" class="text-blue-400">Login</a>`
    : `No account? <a href="#" id="switch-to-register" class="text-blue-400">Register</a>`;
  authError.classList.add('hidden');
  document.body.style.overflow = 'hidden';
  document.getElementById(isRegister ? 'switch-to-login' : 'switch-to-register').addEventListener('click', (e) => {
    e.preventDefault();
    showAuthPopup(!isRegister);
  });
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const isRegister = authTitle.textContent === 'Register';
  const username = usernameInput.value.trim();
  const email = emailInput.value.trim();
  const password = passwordInput.value.trim();

  // Client-side validation
  if (isRegister && (!username || !/^[a-zA-Z0-9_]{3,20}$/.test(username))) {
    authError.textContent = 'Username must be 3-20 characters, alphanumeric';
    authError.classList.remove('hidden');
    return;
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    authError.textContent = 'Invalid email address';
    authError.classList.remove('hidden');
    return;
  }
  if (!password || !/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(password)) {
    authError.textContent = 'Password must be 8+ characters with at least 1 letter and 1 number';
    authError.classList.remove('hidden');
    return;
  }

  try {
    const endpoint = isRegister ? '/register' : '/login';
    const body = isRegister ? { username, email, password } : { email, password };
    console.log('Auth request:', { endpoint, body });
    const response = await fetchWithTimeout(`${BACKEND_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'include'
    });
    const data = await response.json();
    console.log('Auth response:', { status: response.status, data });
    if (!response.ok) throw new Error(data.error || 'Auth failed');
    authPopup.classList.add('hidden');
    document.body.style.overflow = '';
    fetchProfile();
    checkLoginForGame();
    fetchBalance();
  } catch (err) {
    console.error('Auth error:', {
      message: err.message,
      name: err.name,
      stack: err.stack
    });
    authError.textContent = err.message === 'Failed to fetch' ? 'Cannot reach server. Please try again.' : err.message;
    authError.classList.remove('hidden');
  }
}

authSubmit.addEventListener('click', handleAuthSubmit);

// Blackjack Game
const suits = ['♠', '♣', '♥', '♦'];
const values = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];
let deck = [];
let playerHand = [];
let dealerHand = [];
let currentBet = 0;
let gameState = 'idle';

function createDeck() {
  deck = [];
  for (let i = 0; i < 6; i++) {
    for (let suit of suits) {
      for (let value of values) {
        deck.push({ suit, value });
      }
    }
  }
  deck = deck.sort(() => Math.random() - 0.5);
}

function getCardValue(card) {
  if (['J', 'Q', 'K'].includes(card.value)) return 10;
  if (card.value === 'A') return 11;
  return parseInt(card.value);
}

function calculateHandValue(hand) {
  let value = 0;
  let aces = 0;
  for (let card of hand) {
    if (card.value === 'A') {
      aces++;
    } else {
      value += getCardValue(card);
    }
  }
  for (let i = 0; i < aces; i++) {
    if (value + 11 <= 21) {
      value += 11;
    } else {
      value += 1;
    }
  }
  return value;
}

function renderHand(hand, elementId, hideFirst = false) {
  const element = document.getElementById(elementId);
  element.innerHTML = '';
  hand.forEach((card, index) => {
    if (hideFirst && index === 0) {
      element.innerHTML += '<div class="card">?</div>';
    } else {
      const color = ['♥', '♦'].includes(card.suit) ? 'red' : 'black';
      element.innerHTML += `<div class="card ${color}">${card.value}${card.suit}</div>`;
    }
  });
}

async function checkLoginForGame() {
  try {
    const response = await fetchWithTimeout(`${BACKEND_URL}/check-auth`, { credentials: 'include' });
    const data = await response.json();
    console.log('Check Auth:', data);
    if (data.authenticated && data.user.discordConnected) {
      document.getElementById('login-message').classList.add('hidden');
      document.getElementById('game-content').classList.remove('hidden');
      fetchBalance();
    } else {
      document.getElementById('login-message').classList.remove('hidden');
      document.getElementById('game-content').classList.add('hidden');
    }
  } catch (err) {
    console.error('Check Login Error:', err);
    document.getElementById('login-message').classList.remove('hidden');
    document.getElementById('game-content').classList.add('hidden');
  }
}

document.getElementById('deal-btn').addEventListener('click', async () => {
  if (gameState !== 'idle') return;
  const bet = parseInt(document.getElementById('bet-amount').value);
  if (!bet || bet <= 0) {
    document.getElementById('game-status').innerText = 'Invalid bet amount';
    return;
  }
  try {
    const response = await fetch(`${BACKEND_URL}/game/bet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bet }),
      credentials: 'include'
    });
    if (!response.ok) throw new Error(`Bet failed: ${await response.json().error}`);
    const data = await response.json();
    currentBet = bet;
    gameState = 'playing';
    createDeck();
    playerHand = [deck.pop(), deck.pop()];
    dealerHand = [deck.pop(), deck.pop()];
    renderHand(playerHand, 'player-hand');
    renderHand(dealerHand, 'dealer-hand', true);
    document.getElementById('game-actions').classList.remove('hidden');
    document.getElementById('game-status').innerText = '';
    fetchBalance();
    if (dealerHand[1].value === 'A') {
      document.getElementById('insurance-btn').classList.remove('hidden');
    }
    if (playerHand[0].value === playerHand[1].value) {
      document.getElementById('split-btn').classList.remove('hidden');
    }
  } catch (err) {
    console.error('Bet Error:', err);
    document.getElementById('game-status').innerText = err.message;
  }
});

// Game actions (to be completed)
document.getElementById('hit-btn').addEventListener('click', () => {
  // Implement hit logic
});

document.getElementById('stay-btn').addEventListener('click', () => {
  // Implement stay logic
});

// Leaderboard
async function fetchLeaderboard(page) {
  try {
    const response = await fetchWithTimeout(`${BACKEND_URL}/leaderboard?page=${page}`, { credentials: 'include' });
    if (!response.ok) throw new Error(`Leaderboard fetch failed: ${response.status}`);
    const data = await response.json();
    const tbody = document.getElementById('leaderboard-body');
    tbody.innerHTML = '';
    data.users.forEach((user, index) => {
      const rank = (data.page - 1) * 20 + index + 1;
      tbody.innerHTML += `
        <tr>
          <td class="p-2">${rank}</td>
          <td class="p-2">${user.username}</td>
          <td class="p-2">${user.chips}</td>
          <td class="p-2">${user.gamesPlayed}</td>
        </tr>
      `;
    });
    const pagination = document.getElementById('pagination');
    pagination.innerHTML = '';
    for (let i = 1; i <= data.pages; i++) {
      pagination.innerHTML += `<button class="mx-1 p-2 ${i === data.page ? 'bg-blue-600' : 'bg-gray-600'} hover:bg-blue-700 rounded" onclick="fetchLeaderboard(${i})">${i}</button>`;
    }
  } catch (err) {
    console.error('Leaderboard Error:', err);
    document.getElementById('leaderboard-body').innerHTML = '<tr><td colspan="4">Error loading leaderboard</td></tr>';
  }
}

// Profile
async function fetchProfile() {
  const content = document.getElementById('profile-content');
  try {
    const response = await fetchWithTimeout(`${BACKEND_URL}/profile`, { credentials: 'include' });
    console.log('Profile Fetch Status:', response.status);
    if (response.ok) {
      const user = await response.json();
      content.innerHTML = `
        <div class="profile-card">
          <img src="${user.avatar || 'https://via.placeholder.com/100'}" class="rounded-full w-32 h-32 mb-4 mx-auto">
          <h3 class="text-2xl mb-2">${user.username}</h3>
          <p class="text-lg mb-1">Email: ${user.email}</p>
          <p class="text-lg mb-1">Chips: ${user.chips}</p>
          <p class="text-lg mb-1">Games Played: ${user.gamesPlayed}</p>
          <p class="text-lg mb-1">Wins: ${user.wins}</p>
          <p class="text-lg mb-1">Losses: ${user.losses}</p>
          <p class="text-lg mb-1">Total Bets: ${user.totalBets}</p>
          <div class="${user.discordConnected ? 'discord-connected' : 'discord-login'} mt-4">
            ${user.discordConnected
              ? '<span class="bg-[#5865F2] text-white p-2 rounded flex items-center"><i class="fab fa-discord mr-2"></i>Connected</span>'
              : `<a href="${BACKEND_URL}/auth/discord" class="bg-[#5865F2] text-white p-2 rounded flex items-center"><i class="fab fa-discord mr-2"></i>Connect Discord</a>`}
          </div>
        </div>
      `;
      fetchBalance();
    } else {
      showAuthPopup(true);
    }
  } catch (err) {
    console.error('Profile Error:', err);
    showAuthPopup(true);
  }
}

// Balance
async function fetchBalance() {
  try {
    const response = await fetchWithTimeout(`${BACKEND_URL}/balance`, { credentials: 'include' });
    console.log('Balance Fetch Status:', response.status);
    if (response.ok) {
      const data = await response.json();
      document.getElementById('chip-count').innerText = data.chips;
    } else {
      document.getElementById('chip-count').innerText = '0';
    }
  } catch (err) {
    console.error('Balance Error:', err);
    document.getElementById('chip-count').innerText = 'Error';
  }
}

// Fetch with timeout
async function fetchWithTimeout(url, options = {}) {
  const { timeout = 30000, ...fetchOptions } = options; // Increased to 30s
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...fetchOptions, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    console.error('Fetch failed:', { url, error: error.message, name: error.name });
    throw error;
  }
}

// Initialize
async function initialize() {
  try {
    const response = await fetchWithTimeout(`${BACKEND_URL}/check-auth`, { credentials: 'include' });
    if (response.ok) {
      const data = await response.json();
      if (data.authenticated) {
        initializePage();
        fetchBalance();
        return;
      }
    }
    showAuthPopup(true);
  } catch (err) {
    console.error('Init Error:', err);
    showAuthPopup(true);
  }
}

initialize();
setInterval(fetchBalance, 5000);