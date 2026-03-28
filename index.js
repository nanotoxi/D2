import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import Stripe from 'stripe';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { query } from './db.js';

// One-time auto-login tokens (signup → dashboard redirect)
const autoLoginTokens = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of autoLoginTokens) {
    if (v.expiresAt < now) autoLoginTokens.delete(k);
  }
}, 60_000);

const {
  PORT = '4242',
  APP_URL = 'http://localhost:5173',
  DASHBOARD_URL = 'http://localhost:3000',
  CORS_ORIGINS = '',
  STRIPE_SECRET_KEY,
  STRIPE_INDIVIDUAL_PRICE_ID,
  COOKIE_SECURE = 'false',
  ML_API_URL = 'http://localhost:5000',
} = process.env;

if (!STRIPE_SECRET_KEY) throw new Error('Missing STRIPE_SECRET_KEY in environment.');
if (!STRIPE_INDIVIDUAL_PRICE_ID) throw new Error('Missing STRIPE_INDIVIDUAL_PRICE_ID in environment.');

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2025-01-27.acacia' });

const app = express();
// Allow requests from landing page, dashboard, and any extra origins in CORS_ORIGINS
const allowedOrigins = [
  APP_URL,
  DASHBOARD_URL,
  ...CORS_ORIGINS.split(',').map(o => o.trim()),
].filter(Boolean);
console.log('Allowed CORS origins:', allowedOrigins);

function isOriginAllowed(origin) {
  if (!origin) return true;
  if (allowedOrigins.includes(origin)) return true;
  // Allow all Vercel and Railway preview/production deployments
  if (origin.endsWith('.vercel.app')) return true;
  if (origin.endsWith('.railway.app')) return true;
  return false;
}

app.use(cors({
  origin: (origin, callback) => {
    if (isOriginAllowed(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: COOKIE_SECURE === 'true',
  path: '/',
};

function safeJsonParse(input) {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}

function createTrialExpiry(days) {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function getAuthSession(req) {
  const raw = req.cookies?.auth_session;
  if (!raw) return null;
  return safeJsonParse(raw);
}
function setAuthSession(res, session) {
  res.cookie('auth_session', JSON.stringify(session), COOKIE_OPTIONS);
}
function clearAuthSession(res) {
  res.clearCookie('auth_session', { path: '/' });
}

function getStripeCustomerId(req) {
  return req.cookies?.stripe_customer_id || null;
}
function setStripeCustomerId(res, customerId) {
  res.cookie('stripe_customer_id', customerId, COOKIE_OPTIONS);
}
function clearStripeCustomerId(res) {
  res.clearCookie('stripe_customer_id', { path: '/' });
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const session = {
      email: user.email,
      name: user.name,
      role: user.role,
      trialExpiry: user.role === 'developer' ? null : (user.trial_expiry ? new Date(user.trial_expiry).toISOString() : createTrialExpiry(1)),
    };

    setAuthSession(res, session);
    return res.json({ user: session });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password || !name) return res.status(400).json({ error: 'Missing fields' });

    const trialExpiry = createTrialExpiry(1);
    const passwordHash = await bcrypt.hash(password, 10);

    await query(
      'INSERT INTO users (email, password_hash, name, trial_expiry) VALUES ($1, $2, $3, $4)',
      [email, passwordHash, name, trialExpiry]
    );

    const session = { email, name, role: 'user', trialExpiry };
    setAuthSession(res, session);
    // Generate one-time token for cross-domain auto-login to dashboard
    const autoLoginToken = crypto.randomUUID();
    autoLoginTokens.set(autoLoginToken, { session, expiresAt: Date.now() + 90_000 });
    return res.json({ user: session, autoLoginToken });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already in use' });
    }
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.get('/api/auth/me', (req, res) => {
  const session = getAuthSession(req);
  if (!session) return res.json({ user: null });

  const stripeCustomerId = getStripeCustomerId(req);
  const isDeveloper = session.role === 'developer';
  const expiry = session.trialExpiry ? new Date(session.trialExpiry).getTime() : null;
  const isExpired = expiry ? Date.now() > expiry : false;
  const hasStripeSubscription = Boolean(stripeCustomerId);
  const hasAccess = isDeveloper || hasStripeSubscription || !isExpired;

  return res.json({ user: session, isExpired, isDeveloper, hasAccess, hasStripeSubscription });
});

app.post('/api/auth/logout', (_req, res) => {
  clearAuthSession(res);
  clearStripeCustomerId(res);
  return res.json({ success: true });
});

// Exchange one-time token for session (cross-domain signup → dashboard)
app.post('/api/auth/exchange-token', (req, res) => {
  const { token } = req.body || {};
  const entry = token && autoLoginTokens.get(token);
  if (!entry || entry.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  autoLoginTokens.delete(token);
  return res.json({ user: entry.session });
});

// ─────────────────────────────────────────────────────────────────────────────
// Simulations
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/simulations', async (req, res) => {
  try {
    const session = getAuthSession(req);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    const { nanoparticle_id, core_size, zeta_potential, surface_area, dosage, exposure_time, toxicity_prediction, confidence, cytotoxicity, risk_level } = req.body || {};
    await query(
      `INSERT INTO simulations (user_email, particle_id, core_size, zeta_potential, surface_area, dosage, exposure_time, toxicity_prediction, confidence, cytotoxicity, risk_level)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [session.email, nanoparticle_id, core_size, zeta_potential, surface_area, dosage, exposure_time, toxicity_prediction, confidence, cytotoxicity, risk_level]
    );
    return res.json({ success: true });
  } catch (err) {
    console.error('Simulation save error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.get('/api/simulations', async (req, res) => {
  try {
    const session = getAuthSession(req);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });

    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);

    const result = await query(
      `SELECT * FROM simulations WHERE user_email = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [session.email, limit, offset]
    );

    return res.json({ simulations: result.rows, total: result.rows.length, limit, offset });
  } catch (err) {
    console.error('Simulations fetch error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Stats Overview
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/stats/overview', async (req, res) => {
  try {
    const session = getAuthSession(req);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });

    const email = session.email;

    const [totalRes, toxicRes, safeRes, avgConfRes, dailyRes] = await Promise.all([
      query('SELECT COUNT(*) AS total FROM simulations WHERE user_email = $1', [email]),
      query("SELECT COUNT(*) AS cnt FROM simulations WHERE user_email = $1 AND toxicity_result = 'TOXIC'", [email]),
      query("SELECT COUNT(*) AS cnt FROM simulations WHERE user_email = $1 AND toxicity_result IN ('SAFE', 'NON-TOXIC')", [email]),
      query('SELECT AVG(confidence) AS avg_conf FROM simulations WHERE user_email = $1', [email]),
      query(
        `SELECT
           DATE(created_at) AS day,
           COUNT(*) AS count,
           COUNT(*) FILTER (WHERE toxicity_result = 'TOXIC') AS toxic_count,
           COUNT(*) FILTER (WHERE toxicity_result IN ('SAFE','NON-TOXIC')) AS safe_count
         FROM simulations
         WHERE user_email = $1 AND created_at >= NOW() - INTERVAL '90 days'
         GROUP BY DATE(created_at)
         ORDER BY day ASC`,
        [email]
      ),
    ]);

    return res.json({
      total: parseInt(totalRes.rows[0]?.total || '0', 10),
      toxic_count: parseInt(toxicRes.rows[0]?.cnt || '0', 10),
      safe_count: parseInt(safeRes.rows[0]?.cnt || '0', 10),
      avg_confidence: parseFloat(avgConfRes.rows[0]?.avg_conf || '0'),
      daily_series: dailyRes.rows,
    });
  } catch (err) {
    console.error('Stats overview error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Predict — proxy to Python ML backend and save to DB
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/predict', async (req, res) => {
  try {
    const session = getAuthSession(req);
    const body = req.body || {};

    // Forward to Python ML backend
    const mlRes = await fetch(`${ML_API_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!mlRes.ok) {
      const errText = await mlRes.text();
      return res.status(mlRes.status).json({ error: errText });
    }

    const mlData = await mlRes.json();

    // Parse ML response fields
    const stage1 = mlData.stage1 || {};
    const stage2 = mlData.stage2 || {};
    const stage3 = mlData.stage3 || {};

    const aggregationFactor = parseFloat(String(stage1.aggregation_factor || '0').replace('x', '')) || null;
    const hydrodynamicDiameter = parseFloat(stage1.predicted_hydrodynamic_diameter || '0') || null;

    const toxicityResult = stage2.toxicity_prediction || null;
    const confidence = stage2.confidence != null ? parseFloat(stage2.confidence) : null;
    const riskScore = stage2.composite_score != null ? parseFloat(stage2.composite_score) : null;

    // Build a unique request_id
    const requestId = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    // Save to simulations table
    await query(
      `INSERT INTO simulations (
        request_id, user_email, particle_id, material,
        core_size, zeta_potential, surface_area, bandgap_energy,
        dosage, exposure_time, env_ph, protein_corona,
        aggregation_factor, hydrodynamic_diameter, zeta_shift,
        toxicity_result, confidence, risk_score,
        ros_generation, apoptosis_likelihood, necrosis_likelihood,
        primary_pathway, explanation, raw_response
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
      [
        requestId,
        session ? session.email : null,
        body.nanoparticle_id || mlData.nanoparticle_id || null,
        body.material || null,
        body.core_size || null,
        body.zeta_potential || null,
        body.surface_area || null,
        body.bandgap_energy || null,
        body.dosage || null,
        body.exposure_time || null,
        body.environmental_pH || null,
        body.protein_corona != null ? Boolean(body.protein_corona) : null,
        aggregationFactor,
        hydrodynamicDiameter,
        null, // zeta_shift not returned by current ML backend
        toxicityResult,
        confidence,
        riskScore,
        null, // ros_generation — stage3 currently returns YES/NO cytotoxicity only
        null, // apoptosis_likelihood
        null, // necrosis_likelihood
        null, // primary_pathway
        mlData.explanation || null,
        JSON.stringify(mlData),
      ]
    );

    return res.json(mlData);
  } catch (err) {
    console.error('Predict proxy error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Checkout
// ─────────────────────────────────────────────────────────────────────────────
const PRICE_MAP = { individual: STRIPE_INDIVIDUAL_PRICE_ID };

app.post('/api/checkout', async (req, res) => {
  try {
    const { planId } = req.body || {};
    const priceId = PRICE_MAP[planId];
    if (!priceId) return res.status(400).json({ error: 'Unknown planId' });

    const existingCustomerId = getStripeCustomerId(req);

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      subscription_data: existingCustomerId ? undefined : { trial_period_days: 14 },
      customer: existingCustomerId || undefined,
      success_url: `${DASHBOARD_URL}/api/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/#subscription`,
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error('Error creating checkout session:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.get('/api/checkout/success', async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    if (!sessionId || typeof sessionId !== 'string') return res.status(400).json({ error: 'Missing session_id' });

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const customerId = typeof session.customer === 'string' ? session.customer : session.customer?.id;
    if (!customerId) return res.status(400).json({ error: 'No customer on session' });

    const email = session.customer_details?.email || 'user@nanotoxi.com';
    const name = session.customer_details?.name || email.split('@')[0];

    setStripeCustomerId(res, customerId);
    return res.json({ customerId, email, name });
  } catch (err) {
    console.error('Error handling checkout success:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Billing
// ─────────────────────────────────────────────────────────────────────────────
function formatMoney(amountCents, currency) {
  const n = typeof amountCents === 'number' ? amountCents : 0;
  const c = (currency || 'usd').toUpperCase();
  return `${c} ${(n / 100).toFixed(2)}`;
}

function formatMonthFromUnix(seconds) {
  return new Date(seconds * 1000).toLocaleString('en-US', { month: 'long', year: 'numeric' });
}

app.get('/api/billing', async (req, res) => {
  try {
    const customerId = getStripeCustomerId(req);
    if (!customerId) return res.json({ subscription: null, invoices: [], currentPlanId: null });

    const subs = await stripe.subscriptions.list({
      customer: customerId,
      status: 'all',
      limit: 1,
      expand: ['data.items.data.price.product'],
    });
    const subscription = subs.data[0] || null;

    const invoicesRes = await stripe.invoices.list({ customer: customerId, limit: 12 });

    if (!subscription) {
      return res.json({
        subscription: null,
        invoices: invoicesRes.data.map((inv) => ({
          id: inv.id,
          month: formatMonthFromUnix(inv.created),
          plan: inv.lines?.data?.[0]?.description || 'Subscription',
          amount: formatMoney(inv.amount_paid ?? inv.amount_due ?? 0, inv.currency),
          status: (inv.status || 'unknown').toString(),
        })),
        currentPlanId: null,
      });
    }

    const item = subscription.items.data[0];
    const price = item?.price;
    const product = price?.product;
    const planName = typeof product === 'object' && product?.name ? product.name : 'Subscription';

    const cancelAtPeriodEnd = Boolean(subscription.cancel_at_period_end);
    const nextBilling = new Date(subscription.current_period_end * 1000).toLocaleDateString('en-US', {
      month: 'short',
      day: '2-digit',
      year: 'numeric',
    });

    const priceLabel =
      price?.unit_amount != null
        ? `${formatMoney(price.unit_amount, price.currency)}/${price.recurring?.interval || 'month'}`
        : '—';

    const stripeStatus = subscription.status;
    const statusLabel =
      stripeStatus === 'active' ? 'Active'
        : stripeStatus === 'trialing' ? 'Trial'
          : stripeStatus === 'canceled' ? 'Canceled'
            : stripeStatus === 'past_due' ? 'Past Due'
              : stripeStatus === 'unpaid' ? 'Unpaid'
                : (stripeStatus || 'Unknown');

    const invoices = invoicesRes.data.map((inv) => ({
      id: inv.id,
      month: formatMonthFromUnix(inv.created),
      plan: inv.lines?.data?.[0]?.description || planName,
      amount: formatMoney(inv.amount_paid ?? inv.amount_due ?? 0, inv.currency),
      status: (inv.status || 'unknown').toString(),
    }));

    return res.json({
      subscription: {
        id: subscription.id,
        planName,
        price: priceLabel,
        nextBilling,
        status: statusLabel,
        stripeStatus,
        cancelAtPeriodEnd,
      },
      invoices,
      currentPlanId: 'individual',
    });
  } catch (err) {
    console.error('Error fetching billing:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/api/billing/cancel', async (req, res) => {
  try {
    const { subscriptionId } = req.body || {};
    if (!subscriptionId) return res.status(400).json({ error: 'Missing subscriptionId' });

    const updated = await stripe.subscriptions.update(subscriptionId, { cancel_at_period_end: true });
    return res.json({
      status: updated.status,
      cancelAtPeriodEnd: updated.cancel_at_period_end,
      currentPeriodEnd: updated.current_period_end,
    });
  } catch (err) {
    console.error('Error canceling subscription:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/api/billing/resume', async (req, res) => {
  try {
    const { subscriptionId } = req.body || {};
    if (!subscriptionId) return res.status(400).json({ error: 'Missing subscriptionId' });

    const updated = await stripe.subscriptions.update(subscriptionId, { cancel_at_period_end: false });
    return res.json({ status: updated.status, cancelAtPeriodEnd: updated.cancel_at_period_end });
  } catch (err) {
    console.error('Error resuming subscription:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.listen(Number(PORT), () => {
  console.log(`Stripe backend listening on http://localhost:${PORT}`);
});
