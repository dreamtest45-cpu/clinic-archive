const crypto = require('crypto');

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function getSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 8) {
    throw new Error('SESSION_SECRET غير مضبوط أو قصير جداً. أضف قيمة عشوائية طويلة في متغيرات البيئة.');
  }
  return secret;
}

function sign(payload) {
  return crypto.createHmac('sha256', getSecret()).update(payload).digest('hex');
}

function issueToken() {
  const expires = Date.now() + SESSION_TTL_MS;
  const payload = String(expires);
  return payload + '.' + sign(payload);
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payload, sig] = parts;
  let expected;
  try {
    expected = sign(payload);
  } catch (e) {
    return false;
  }
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  const expires = Number(payload);
  if (!Number.isFinite(expires) || expires < Date.now()) return false;
  return true;
}

// Small in-memory brute-force guard for the login endpoint (single-instance app).
const attempts = new Map(); // ip -> {count, resetAt}
const MAX_ATTEMPTS = 12;
const WINDOW_MS = 15 * 60 * 1000;

function tooManyAttempts(ip) {
  const rec = attempts.get(ip);
  if (!rec) return false;
  if (Date.now() > rec.resetAt) { attempts.delete(ip); return false; }
  return rec.count >= MAX_ATTEMPTS;
}
function recordFailure(ip) {
  const rec = attempts.get(ip);
  if (!rec || Date.now() > rec.resetAt) {
    attempts.set(ip, { count: 1, resetAt: Date.now() + WINDOW_MS });
  } else {
    rec.count++;
  }
}
function clearFailures(ip) {
  attempts.delete(ip);
}

module.exports = { issueToken, verifyToken, tooManyAttempts, recordFailure, clearFailures, SESSION_TTL_MS };
