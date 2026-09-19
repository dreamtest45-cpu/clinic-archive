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

// A short fingerprint of the current clinic password, keyed by SESSION_SECRET
// (never the raw password itself). Embedding this in the session token means
// changing CLINIC_PASSWORD on Railway instantly invalidates every session
// issued under the old password — important if a device is lost/stolen or a
// staff member leaves and the clinic changes the password as a precaution.
function pwFingerprint() {
  const expected = process.env.CLINIC_PASSWORD || '';
  return crypto.createHmac('sha256', getSecret()).update('pw:' + expected).digest('hex').slice(0, 16);
}

function issueToken() {
  const expires = Date.now() + SESSION_TTL_MS;
  const payload = String(expires) + '.' + pwFingerprint();
  return payload + '.' + sign(payload);
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [expiresStr, fp, sig] = parts;
  const payload = expiresStr + '.' + fp;
  let expected;
  try {
    expected = sign(payload);
  } catch (e) {
    return false;
  }
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  const expires = Number(expiresStr);
  if (!Number.isFinite(expires) || expires < Date.now()) return false;
  let currentFp;
  try {
    currentFp = pwFingerprint();
  } catch (e) {
    return false;
  }
  const fa = Buffer.from(fp);
  const fb = Buffer.from(currentFp);
  if (fa.length !== fb.length || !crypto.timingSafeEqual(fa, fb)) return false;
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
