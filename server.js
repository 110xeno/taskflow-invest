require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { DatabaseSync } = require('node:sqlite');
const Stripe = require('stripe');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = process.env.DB_FILE || path.join(DATA_DIR, 'taskflow.db');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-this-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const COOKIE_NAME = 'taskflow_session';
const APP_URL = process.env.APP_URL || '';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_PRO = process.env.STRIPE_PRICE_PRO || '';
const STRIPE_PRICE_PRO_MONTHLY = process.env.STRIPE_PRICE_PRO_MONTHLY || '';
const STRIPE_PRICE_PRO_YEARLY = process.env.STRIPE_PRICE_PRO_YEARLY || '';
const STARTER_TASK_LIMIT = Number(process.env.STARTER_TASK_LIMIT || '25');
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'dev-only-change-this-secret') {
  throw new Error('JWT_SECRET must be set in production.');
}

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
const dbDir = path.dirname(DB_FILE);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

function prepare(sql) {
  const statement = db.prepare(sql);
  statement.setAllowBareNamedParameters(true);
  return statement;
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    due TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    assignee TEXT NOT NULL,
    avatar TEXT NOT NULL,
    budget TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

function ensureColumns(tableName, columns) {
  const existing = prepare(`PRAGMA table_info(${tableName})`).all().map((row) => row.name);
  columns.forEach((col) => {
    if (!existing.includes(col.name)) {
      db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${col.name} ${col.type}`);
    }
  });
}

ensureColumns('users', [
  { name: 'plan', type: 'TEXT' },
  { name: 'plan_status', type: 'TEXT' },
  { name: 'stripe_customer_id', type: 'TEXT' },
  { name: 'stripe_subscription_id', type: 'TEXT' },
  { name: 'plan_renews_at', type: 'TEXT' }
]);

ensureColumns('tasks', [
  { name: 'tier', type: 'TEXT' },
  { name: 'currency', type: 'TEXT' },
  { name: 'cost_amount', type: 'REAL' },
  { name: 'roi_pct', type: 'REAL' }
]);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map((origin) => origin.trim()),
  credentials: true
}));

// Stripe webhooks need the raw body for signature verification.
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send('Stripe not configured');
  }

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const customerId = session.customer;
        const subscriptionId = session.subscription;
        const userId = session.metadata?.userId;

        let user = null;
        if (userId) {
          user = prepare('SELECT id FROM users WHERE id = ?').get(userId);
        }
        if (!user && customerId) {
          user = prepare('SELECT id FROM users WHERE stripe_customer_id = ?').get(customerId);
        }
        if (user) {
          prepare(`
            UPDATE users
            SET plan = ?, plan_status = ?, stripe_customer_id = COALESCE(stripe_customer_id, ?), stripe_subscription_id = ?
            WHERE id = ?
          `).run('pro', 'active', customerId || null, subscriptionId || null, user.id);
        }
        break;
      }
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const status = String(sub.status || '');
        const customerId = sub.customer;
        const renewsAt = sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;

        const user = prepare('SELECT id FROM users WHERE stripe_customer_id = ?').get(customerId);
        if (user) {
          const mappedStatus = status === 'active' ? 'active' : status || 'unknown';
          prepare(`
            UPDATE users
            SET plan = ?, plan_status = ?, stripe_subscription_id = ?, plan_renews_at = ?
            WHERE id = ?
          `).run(mappedStatus === 'active' ? 'pro' : 'starter', mappedStatus, sub.id, renewsAt, user.id);
        }
        break;
      }
      default:
        break;
    }
  } catch (err) {
    return res.status(500).send('Webhook handler error');
  }

  res.json({ received: true });
});

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname)));

function nowIso() {
  return new Date().toISOString();
}

function createId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.created_at || null,
    isAdmin: isAdminUser(user)
  };
}

function createToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function isProUser(user) {
  return String(user.plan || '').toLowerCase() === 'pro' && String(user.plan_status || '').toLowerCase() === 'active';
}

function isAdminUser(user) {
  // If not configured, default to allowing task management (dev-friendly).
  if (!ADMIN_EMAILS.length) return true;
  const email = String(user?.email || '').trim().toLowerCase();
  return Boolean(email) && ADMIN_EMAILS.includes(email);
}

function requireAdmin(req, res, next) {
  if (!isAdminUser(req.user)) {
    return res.status(403).json({
      message: 'Only the company account can create or manage tasks.',
      code: 'admin_required'
    });
  }
  next();
}

function requirePro(req, res, next) {
  if (!isProUser(req.user)) {
    return res.status(402).json({
      message: 'This feature requires Pro. Upgrade to continue.',
      code: 'pro_required'
    });
  }
  next();
}

function getBaseUrl(req) {
  if (APP_URL) return APP_URL.replace(/\/+$/, '');
  const proto = (req.headers['x-forwarded-proto'] || 'http').toString().split(',')[0].trim();
  const host = req.headers.host;
  return `${proto}://${host}`;
}

function readCookie(req, name) {
  const cookies = req.headers.cookie || '';
  return cookies
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function normalizeTaskInput(task, existing = {}) {
  const assignee = String(task.assignee || existing.assignee || 'Unassigned').trim();
  const priority = ['High', 'Medium', 'Low'].includes(task.priority) ? task.priority : existing.priority || 'Medium';
  const status = ['todo', 'progress', 'done', 'blocked'].includes(task.status) ? task.status : existing.status || 'todo';
  const tier = ['silver', 'gold', 'diamond'].includes(String(task.tier || '').toLowerCase())
    ? String(task.tier).toLowerCase()
    : (existing.tier || 'silver');
  const currency = String(task.currency || existing.currency || 'USDT').trim().toUpperCase();
  const costAmountRaw = task.costAmount ?? task.cost_amount ?? existing.costAmount ?? existing.cost_amount ?? null;
  const costAmount = costAmountRaw === null || costAmountRaw === undefined || costAmountRaw === ''
    ? (existing.costAmount ?? existing.cost_amount ?? null)
    : Number(costAmountRaw);
  const roiPctRaw = task.roiPct ?? task.roi_pct ?? existing.roiPct ?? existing.roi_pct ?? null;
  const roiPctFromTier = tier === 'gold' ? 30 : tier === 'diamond' ? 50 : 10;

  // ROI is fixed by tier per product rules; ignore any custom value coming from clients.
  void roiPctRaw;
  const roiPct = roiPctFromTier;

  // Enforce cost ranges per tier (investment in crypto, but numeric amount still needs guardrails).
  const ranges = {
    silver: { min: 10, max: 250 },
    gold: { min: 300, max: 800 },
    diamond: { min: 1000, max: 4500 }
  };
  const range = ranges[tier] || ranges.silver;
  const costOk = Number.isFinite(Number(costAmount)) && Number(costAmount) >= range.min && Number(costAmount) <= range.max;

  return {
    title: String(task.title || existing.title || '').trim(),
    description: String(task.description || existing.description || '').trim(),
    due: String(task.due || existing.due || new Date().toISOString().slice(0, 10)).trim(),
    priority,
    status,
    assignee,
    avatar: String(task.avatar || existing.avatar || assignee.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2)).trim(),
    budget: String(task.budget || existing.budget || '$0').trim(),
    value: String(task.value || existing.value || '$0').trim(),
    tier,
    currency,
    costAmount: Number.isFinite(costAmount) ? costAmount : null,
    roiPct: Number.isFinite(roiPct) ? roiPct : null,
    _costRange: { ...range, ok: costOk }
  };
}

function rowToTask(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    due: row.due,
    priority: row.priority,
    status: row.status,
    assignee: row.assignee,
    avatar: row.avatar,
    budget: row.budget,
    value: row.value,
    tier: row.tier || 'silver',
    currency: row.currency || 'USDT',
    costAmount: row.cost_amount ?? null,
    roiPct: row.roi_pct ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : readCookie(req, COOKIE_NAME);
  if (!token) {
    return res.status(401).json({ message: 'Authentication is required.' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = prepare('SELECT id, name, email, created_at, plan, plan_status FROM users WHERE id = ?').get(payload.sub);
    if (!user) {
      return res.status(401).json({ message: 'User no longer exists.' });
    }
    req.user = user;
    next();
  } catch (_error) {
    return res.status(401).json({ message: 'Invalid or expired session.' });
  }
}

function seedDefaultTasksForUser(userId) {
  const existing = prepare('SELECT COUNT(*) AS count FROM tasks WHERE user_id = ?').get(userId);
  if (existing.count > 0) return;

  const insert = prepare(`
    INSERT INTO tasks (id, user_id, title, description, due, priority, status, assignee, avatar, budget, value, tier, currency, cost_amount, roi_pct, created_at, updated_at)
    VALUES (@id, @userId, @title, @description, @due, @priority, @status, @assignee, @avatar, @budget, @value, @tier, @currency, @costAmount, @roiPct, @createdAt, @updatedAt)
  `);

  // Starter tasks are intentionally practical and product-facing: enough to make a new account feel "alive"
  // without turning the first screen into a wall of noise.
  function pick(min, max) {
    const a = Number(min);
    const b = Number(max);
    return Math.round((a + Math.random() * (b - a)) * 100) / 100;
  }

  function expected(costAmount, roiPct) {
    const cost = Number(costAmount) || 0;
    const pct = Number(roiPct) || 0;
    return Math.round((cost * (1 + pct / 100)) * 100) / 100;
  }

  const defaults = [
    {
      title: 'Fast USDT Flip (Silver)',
      description: 'Quick-turn opportunity. Target: first result in under 60 minutes after subscribing. Risk varies; use proper sizing.',
      due: new Date().toISOString().slice(0, 10),
      priority: 'High',
      status: 'progress',
      assignee: 'Launch Team',
      tier: 'silver',
      currency: 'USDT',
      costAmount: pick(10, 250),
      roiPct: 10
    },
    {
      title: 'Momentum Trade (Silver)',
      description: 'Designed for speed and clarity. Target: under 60 minutes to a measurable move after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 3).toISOString().slice(0, 10),
      priority: 'Medium',
      status: 'todo',
      assignee: 'Product',
      tier: 'silver',
      currency: 'USDT',
      costAmount: pick(10, 250),
      roiPct: 10
    },
    {
      title: 'Breakout Setup (Gold)',
      description: 'Higher conviction, wider move. Target: under 60 minutes to activation after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 2).toISOString().slice(0, 10),
      priority: 'High',
      status: 'todo',
      assignee: 'Frontend',
      tier: 'gold',
      currency: 'USDT',
      costAmount: pick(300, 800),
      roiPct: 30
    },
    {
      title: 'News Catalyst Play (Gold)',
      description: 'Time-sensitive opportunity. Target: under 60 minutes to the first signal after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 4).toISOString().slice(0, 10),
      priority: 'Medium',
      status: 'todo',
      assignee: 'Frontend',
      tier: 'gold',
      currency: 'USDT',
      costAmount: pick(300, 800),
      roiPct: 30
    },
    {
      title: 'Scalp Strategy Pack (Silver)',
      description: 'Simple steps, fast loop. Target: under 60 minutes to a trade-ready setup after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 5).toISOString().slice(0, 10),
      priority: 'Medium',
      status: 'todo',
      assignee: 'Product',
      tier: 'silver',
      currency: 'USDT',
      costAmount: pick(10, 250),
      roiPct: 10
    },
    {
      title: 'High-Impact Swing (Diamond)',
      description: 'Bigger range, bigger responsibility. Target: under 60 minutes to the first trigger after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 7).toISOString().slice(0, 10),
      priority: 'High',
      status: 'todo',
      assignee: 'Backend',
      tier: 'diamond',
      currency: 'USDT',
      costAmount: pick(1000, 4500),
      roiPct: 50
    },
    {
      title: 'Liquidity Grab (Silver)',
      description: 'Low-friction entry, quick target. Target: under 60 minutes to the first outcome after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 8).toISOString().slice(0, 10),
      priority: 'Low',
      status: 'todo',
      assignee: 'Backend',
      tier: 'silver',
      currency: 'USDT',
      costAmount: pick(10, 250),
      roiPct: 10
    },
    {
      title: 'Volatility Burst (Gold)',
      description: 'For active markets. Target: under 60 minutes to confirmation after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 6).toISOString().slice(0, 10),
      priority: 'Low',
      status: 'todo',
      assignee: 'Design',
      tier: 'gold',
      currency: 'USDT',
      costAmount: pick(300, 800),
      roiPct: 30
    },
    {
      title: 'Whale Trail (Diamond)',
      description: 'Aggressive tier. Target: under 60 minutes to the first actionable signal after subscribing. Risk varies.',
      due: new Date(Date.now() + 86400000 * 9).toISOString().slice(0, 10),
      priority: 'Low',
      status: 'todo',
      assignee: 'Product',
      tier: 'diamond',
      currency: 'USDT',
      costAmount: pick(1000, 4500),
      roiPct: 50
    }
  ];

  const createdAt = nowIso();
  db.exec('BEGIN');
  try {
    defaults.forEach((item) => {
      const withAmounts = {
        ...item,
        budget: `${item.costAmount} ${item.currency}`,
        value: `${expected(item.costAmount, item.roiPct)} ${item.currency}`
      };
      const task = normalizeTaskInput(withAmounts);
      insert.run({
        id: createId('task'),
        userId,
        ...task,
        createdAt,
        updatedAt: createdAt
      });
    });
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function backfillStarterTasksForUser(userId) {
  const insert = prepare(`
    INSERT INTO tasks (id, user_id, title, description, due, priority, status, assignee, avatar, budget, value, tier, currency, cost_amount, roi_pct, created_at, updated_at)
    VALUES (@id, @userId, @title, @description, @due, @priority, @status, @assignee, @avatar, @budget, @value, @tier, @currency, @costAmount, @roiPct, @createdAt, @updatedAt)
  `);

  // Keep this list in sync with seedDefaultTasksForUser().
  const defaults = [
    {
      title: 'Prepare launch checklist',
      description: 'Review production hosting, database backups, support contact, and privacy notes.',
      due: new Date().toISOString().slice(0, 10),
      priority: 'High',
      status: 'progress',
      assignee: 'Launch Team'
    },
    {
      title: 'Invite first real users',
      description: 'Add the first team members and collect feedback from their task flow.',
      due: new Date(Date.now() + 86400000 * 3).toISOString().slice(0, 10),
      priority: 'Medium',
      status: 'todo',
      assignee: 'Product'
    },
    {
      title: 'Add Arabic support for mobile users',
      description: 'Update the interface and navigation so Arabic users can use the app comfortably.',
      due: new Date(Date.now() + 86400000 * 2).toISOString().slice(0, 10),
      priority: 'High',
      status: 'todo',
      assignee: 'Frontend'
    },
    {
      title: 'Optimize the page for phones',
      description: 'Make sure the mobile layout is clear, fast, and easy to read.',
      due: new Date(Date.now() + 86400000 * 4).toISOString().slice(0, 10),
      priority: 'Medium',
      status: 'todo',
      assignee: 'Frontend'
    },
    {
      title: 'Create onboarding checklist',
      description: 'Add a simple first-run checklist so new teams know what to do next.',
      due: new Date(Date.now() + 86400000 * 5).toISOString().slice(0, 10),
      priority: 'Medium',
      status: 'todo',
      assignee: 'Product'
    },
    {
      title: 'Set up basic roles and permissions',
      description: 'Define Admin and Member permissions for tasks and billing.',
      due: new Date(Date.now() + 86400000 * 7).toISOString().slice(0, 10),
      priority: 'High',
      status: 'todo',
      assignee: 'Backend'
    },
    {
      title: 'Add export and backup option',
      description: 'Allow users to export tasks as JSON for backups and migration.',
      due: new Date(Date.now() + 86400000 * 8).toISOString().slice(0, 10),
      priority: 'Low',
      status: 'todo',
      assignee: 'Backend'
    },
    {
      title: 'Improve empty states',
      description: 'Make empty task lists helpful with clear next actions.',
      due: new Date(Date.now() + 86400000 * 6).toISOString().slice(0, 10),
      priority: 'Low',
      status: 'todo',
      assignee: 'Design'
    },
    {
      title: 'Add analytics dashboard baseline',
      description: 'Ensure charts render with real task data and sensible defaults.',
      due: new Date(Date.now() + 86400000 * 9).toISOString().slice(0, 10),
      priority: 'Low',
      status: 'todo',
      assignee: 'Product'
    }
  ];

  const existingTitles = new Set(
    prepare('SELECT title FROM tasks WHERE user_id = ?').all(userId).map((row) => row.title)
  );

  const createdAt = nowIso();
  let inserted = 0;
  db.exec('BEGIN');
  try {
    defaults.forEach((item) => {
      if (existingTitles.has(item.title)) return;
      const task = normalizeTaskInput(item);
      insert.run({
        id: createId('task'),
        userId,
        ...task,
        createdAt,
        updatedAt: createdAt
      });
      inserted += 1;
    });
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  return { inserted, total: defaults.length };
}

function backfillInvestmentFieldsForUser(userId) {
  // Fill missing tier/currency/cost/roi for existing tasks so UI calculations stay consistent.
  const rows = prepare('SELECT id, title, budget, value, tier, currency, cost_amount AS costAmount, roi_pct AS roiPct FROM tasks WHERE user_id = ?')
    .all(userId);

  const ranges = {
    silver: { min: 10, max: 250, pct: 10 },
    gold: { min: 300, max: 800, pct: 30 },
    diamond: { min: 1000, max: 4500, pct: 50 }
  };

  const pick = (min, max) => Math.round((min + Math.random() * (max - min)) * 100) / 100;

  const update = prepare(`
    UPDATE tasks
    SET tier = COALESCE(tier, @tier),
        currency = COALESCE(currency, @currency),
        cost_amount = COALESCE(cost_amount, @costAmount),
        roi_pct = COALESCE(roi_pct, @roiPct)
    WHERE id = @id AND user_id = @userId
  `);

  let updated = 0;
  db.exec('BEGIN');
  try {
    rows.forEach((row) => {
      if (row.tier && row.currency && row.costAmount !== null && row.roiPct !== null) return;

      // If we can't infer a tier, default to silver.
      const tier = (row.tier && ranges[row.tier]) ? row.tier : 'silver';
      const meta = ranges[tier] || ranges.silver;

      const costAmount = row.costAmount !== null && Number.isFinite(Number(row.costAmount))
        ? Number(row.costAmount)
        : pick(meta.min, meta.max);

      update.run({
        id: row.id,
        userId,
        tier,
        currency: row.currency || 'USDT',
        costAmount,
        roiPct: meta.pct
      });
      updated += 1;
    });
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  return { updated };
}

app.post('/api/register', authLimiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  const normalizedEmail = String(email || '').trim().toLowerCase();

  if (!String(name || '').trim() || !normalizedEmail || !password) {
    return res.status(400).json({ message: 'Name, email, and password are required.' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters.' });
  }

  const existing = prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
  if (existing) {
    return res.status(400).json({ message: 'This email is already registered.' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: createId('user'),
    name: String(name).trim(),
    email: normalizedEmail,
    passwordHash,
    createdAt: nowIso()
  };

  prepare('INSERT INTO users (id, name, email, password_hash, created_at, plan, plan_status) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(user.id, user.name, user.email, user.passwordHash, user.createdAt, 'starter', 'none');
  seedDefaultTasksForUser(user.id);

  const token = createToken(user);
  setAuthCookie(res, token);
  res.status(201).json({ user: publicUser(user), token });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = String(email || '').trim().toLowerCase();

  if (!normalizedEmail || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const user = prepare('SELECT id, name, email, created_at, plan, plan_status, password_hash AS passwordHash FROM users WHERE email = ?').get(normalizedEmail);
  if (!user) {
    return res.status(401).json({ message: 'Incorrect email or password.' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ message: 'Incorrect email or password.' });
  }

  const token = createToken(user);
  setAuthCookie(res, token);
  res.json({ user: publicUser(user), token });
});

app.post('/api/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  });
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// For older test accounts: add missing starter tasks without duplicating existing ones.
app.post('/api/me/backfill-starter-tasks', requireAuth, (req, res) => {
  const result = backfillStarterTasksForUser(req.user.id);
  res.json({ ok: true, ...result });
});

app.post('/api/me/backfill-investments', requireAuth, (req, res) => {
  const result = backfillInvestmentFieldsForUser(req.user.id);
  res.json({ ok: true, ...result });
});

app.put('/api/me', requireAuth, (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!name || !email) {
    return res.status(400).json({ message: 'Name and email are required.' });
  }

  const existing = prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(email, req.user.id);
  if (existing) {
    return res.status(400).json({ message: 'This email is already registered.' });
  }

  prepare('UPDATE users SET name = ?, email = ? WHERE id = ?').run(name, email, req.user.id);
  const user = prepare('SELECT id, name, email FROM users WHERE id = ?').get(req.user.id);
  const token = createToken(user);
  setAuthCookie(res, token);
  res.json({ user: publicUser(user), token });
});

app.get('/api/billing/status', requireAuth, (req, res) => {
  const user = prepare('SELECT plan, plan_status, plan_renews_at FROM users WHERE id = ?').get(req.user.id);
  const count = prepare('SELECT COUNT(*) AS count FROM tasks WHERE user_id = ?').get(req.user.id).count;
  res.json({
    plan: user?.plan || 'starter',
    status: user?.plan_status || 'none',
    renewsAt: user?.plan_renews_at || null,
    starterTaskLimit: STARTER_TASK_LIMIT,
    taskCount: count
  });
});

app.post('/api/billing/create-checkout-session', requireAuth, async (req, res) => {
  const intervalRaw = (req.body?.interval || 'month').toString().toLowerCase();
  const interval = intervalRaw === 'year' || intervalRaw === 'annual' || intervalRaw === 'yearly' ? 'year' : 'month';

  // Backwards compatible: STRIPE_PRICE_PRO can be used as the monthly price.
  const monthlyPrice = STRIPE_PRICE_PRO_MONTHLY || STRIPE_PRICE_PRO;
  const yearlyPrice = STRIPE_PRICE_PRO_YEARLY;
  const priceId = interval === 'year' ? yearlyPrice : monthlyPrice;

  if (!stripe || !priceId) {
    return res.status(503).json({ message: 'Billing is not configured yet.' });
  }

  try {
    const baseUrl = getBaseUrl(req);
    const stored = prepare('SELECT stripe_customer_id FROM users WHERE id = ?').get(req.user.id);
    let customerId = stored?.stripe_customer_id || null;

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        name: req.user.name,
        metadata: { userId: req.user.id }
      });
      customerId = customer.id;
      prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').run(customerId, req.user.id);
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: `${baseUrl}/pricing.html?success=1`,
      cancel_url: `${baseUrl}/pricing.html?canceled=1`,
      metadata: { userId: req.user.id, interval }
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err?.type || err?.name || err);
    const message = (err && typeof err.message === 'string') ? err.message : 'Billing request failed.';
    // Stripe auth errors should not crash the process; surface a clear response to the UI.
    res.status(502).json({ message, code: 'stripe_error' });
  }
});

app.post('/api/billing/portal', requireAuth, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ message: 'Billing is not configured yet.' });
  }

  const stored = prepare('SELECT stripe_customer_id FROM users WHERE id = ?').get(req.user.id);
  if (!stored?.stripe_customer_id) {
    return res.status(400).json({ message: 'No billing profile found for this account.' });
  }
  try {
    const baseUrl = getBaseUrl(req);
    const session = await stripe.billingPortal.sessions.create({
      customer: stored.stripe_customer_id,
      return_url: `${baseUrl}/index.html`
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe portal error:', err?.type || err?.name || err);
    const message = (err && typeof err.message === 'string') ? err.message : 'Billing portal unavailable.';
    res.status(502).json({ message, code: 'stripe_error' });
  }
});

app.get('/api/tasks', requireAuth, (req, res) => {
  const tasks = prepare('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.user.id)
    .map(rowToTask);
  res.json(tasks);
});

app.get('/api/export/tasks.csv', requireAuth, requirePro, (req, res) => {
  const rows = prepare('SELECT title, description, due, priority, status, assignee, created_at, updated_at FROM tasks WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.user.id);

  const esc = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;
  const header = ['Title', 'Description', 'Due', 'Priority', 'Status', 'Assignee', 'CreatedAt', 'UpdatedAt'].join(',');
  const csv = [header].concat(rows.map((row) => [
    esc(row.title),
    esc(row.description),
    esc(row.due),
    esc(row.priority),
    esc(row.status),
    esc(row.assignee),
    esc(row.created_at),
    esc(row.updated_at)
  ].join(','))).join('\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="taskflow-tasks.csv"');
  res.send(csv);
});

app.post('/api/tasks', requireAuth, requireAdmin, (req, res) => {
  if (!isProUser(req.user)) {
    const count = prepare('SELECT COUNT(*) AS count FROM tasks WHERE user_id = ?').get(req.user.id).count;
    if (Number.isFinite(STARTER_TASK_LIMIT) && STARTER_TASK_LIMIT > 0 && count >= STARTER_TASK_LIMIT) {
      return res.status(402).json({
        message: `Starter plan limit reached (${STARTER_TASK_LIMIT} tasks). Upgrade to Pro to add more.`,
        code: 'starter_limit',
        limit: STARTER_TASK_LIMIT,
        current: count
      });
    }
  }

  const task = normalizeTaskInput(req.body || {});
  if (!task.title || !task.description || !task.due || !task.assignee) {
    return res.status(400).json({ message: 'A task requires title, description, due date, and assignee.' });
  }
  if (task.costAmount !== null && task._costRange && !task._costRange.ok) {
    return res.status(400).json({
      message: `Investment amount must be between ${task._costRange.min} and ${task._costRange.max} for ${task.tier} tasks.`,
      code: 'invalid_cost_range',
      tier: task.tier,
      min: task._costRange.min,
      max: task._costRange.max
    });
  }

  const createdAt = nowIso();
  const row = {
    id: createId('task'),
    userId: req.user.id,
    ...task,
    createdAt,
    updatedAt: createdAt
  };

  prepare(`
    INSERT INTO tasks (id, user_id, title, description, due, priority, status, assignee, avatar, budget, value, tier, currency, cost_amount, roi_pct, created_at, updated_at)
    VALUES (@id, @userId, @title, @description, @due, @priority, @status, @assignee, @avatar, @budget, @value, @tier, @currency, @costAmount, @roiPct, @createdAt, @updatedAt)
  `).run(row);

  res.status(201).json(rowToTask({
    id: row.id,
    title: row.title,
    description: row.description,
    due: row.due,
    priority: row.priority,
    status: row.status,
    assignee: row.assignee,
    avatar: row.avatar,
    budget: row.budget,
    value: row.value,
    tier: row.tier,
    currency: row.currency,
    cost_amount: row.costAmount,
    roi_pct: row.roiPct,
    created_at: row.createdAt,
    updated_at: row.updatedAt
  }));
});

app.put('/api/tasks/:id', requireAuth, requireAdmin, (req, res) => {
  const existing = prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) {
    return res.status(404).json({ message: 'Task not found.' });
  }

  const task = normalizeTaskInput(req.body || {}, rowToTask(existing));
  if (!task.title || !task.description || !task.due || !task.assignee) {
    return res.status(400).json({ message: 'A task requires title, description, due date, and assignee.' });
  }
  if (task.costAmount !== null && task._costRange && !task._costRange.ok) {
    return res.status(400).json({
      message: `Investment amount must be between ${task._costRange.min} and ${task._costRange.max} for ${task.tier} tasks.`,
      code: 'invalid_cost_range',
      tier: task.tier,
      min: task._costRange.min,
      max: task._costRange.max
    });
  }

  const updatedAt = nowIso();
  prepare(`
    UPDATE tasks
    SET title = @title, description = @description, due = @due, priority = @priority, status = @status,
        assignee = @assignee, avatar = @avatar, budget = @budget, value = @value,
        tier = @tier, currency = @currency, cost_amount = @costAmount, roi_pct = @roiPct,
        updated_at = @updatedAt
    WHERE id = @id AND user_id = @userId
  `).run({ id: req.params.id, userId: req.user.id, ...task, updatedAt });

  const updated = prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  res.json(rowToTask(updated));
});

app.delete('/api/tasks/:id', requireAuth, requireAdmin, (req, res) => {
  const result = prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ message: 'Task not found.' });
  }
  res.json({ ok: true });
});

app.post('/api/payment-intent', requireAuth, (_req, res) => {
  res.json({
    message: 'Payment gateway integration placeholder. Configure a real gateway before accepting payments.'
  });
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', mode: 'api', database: 'sqlite' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`TaskFlow backend running on http://0.0.0.0:${PORT}`);
});
