require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { pool, migrate } = require('./db');
const { issueToken, verifyToken, tooManyAttempts, recordFailure, clearFailures } = require('./auth');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Railway sits behind a proxy; needed for correct req.ip and secure cookies

// Security headers (nosniff, no framing by other sites, no powered-by, etc).
// The whole app UI is one inline <script>, so script-src needs 'unsafe-inline'
// — this still buys real protection (clickjacking, MIME-sniffing, referrer
// leakage) without requiring a rewrite of the front-end.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
    },
  },
}));

const PORT = process.env.PORT || 3000;
const COOKIE_NAME = 'clinic_session';
const MAX_FILE_BYTES = 6 * 1024 * 1024; // 6MB per attachment
const ALLOWED_MIME = /^image\/(jpeg|png|webp|gif)$|^application\/pdf$/;

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME.test(file.mimetype)) {
      return cb(new Error('نوع الملف غير مدعوم'));
    }
    cb(null, true);
  },
});

// ---------- helpers ----------
function clientIp(req) {
  return req.ip || req.connection.remoteAddress || 'unknown';
}
function isAuthed(req) {
  return verifyToken(req.cookies[COOKIE_NAME]);
}
function requireAuth(req, res, next) {
  if (!isAuthed(req)) return res.status(401).json({ error: 'unauthorized' });
  next();
}
function setSessionCookie(req, res) {
  // req.secure reflects X-Forwarded-Proto via `trust proxy` above, so this is
  // correct both behind Railway's HTTPS edge and in plain local http dev.
  res.cookie(COOKIE_NAME, issueToken(), {
    httpOnly: true,
    sameSite: 'lax',
    secure: req.secure,
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}
function bad(res, msg) { return res.status(400).json({ error: msg }); }
function notFound(res) { return res.status(404).json({ error: 'not_found' }); }
function serverError(res, err) {
  console.error(err);
  return res.status(500).json({ error: 'server_error' });
}
function isUuid(v) {
  return typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}
function str(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}
function isIsoDate(v) {
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(new Date(v + 'T00:00:00Z').getTime());
}
// node-postgres returns DATE columns as JS Date objects (not "YYYY-MM-DD"
// strings) — needed when falling back to an existing row's date on a partial update.
function dateOnly(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return v === null || v === undefined ? null : String(v).slice(0, 10);
}
// The frontend calendar groups appointments by exact "YYYY-MM-DD" string match —
// node-postgres returns DATE columns as Date objects, which JSON.stringify would
// otherwise turn into "YYYY-MM-DDT00:00:00.000Z" and silently break that match.
function apptOut(row) {
  if (!row) return row;
  return { ...row, date: dateOnly(row.date) };
}
// HTTP headers must be ASCII/Latin-1 — Arabic filenames need RFC 5987 encoding
// (a plain ASCII fallback plus a UTF-8 filename* browsers actually display).
function contentDisposition(type, filename) {
  const safe = String(filename || 'file');
  let ascii = safe.replace(/[^\x20-\x7E]/g, '_').replace(/"/g, "'");
  if (!ascii.trim()) ascii = 'file';
  return `${type}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(safe)}`;
}
// The upload's declared MIME type comes from the browser/client and can be
// forged (e.g. a script uploaded while claiming "image/png"). Checking the
// file's actual magic bytes catches that before it's ever stored, on top of
// the fileFilter's mimetype check.
function sniffMime(buf) {
  if (!buf || buf.length < 4) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length >= 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.slice(0, 4).toString('ascii') === 'GIF8') return 'image/gif';
  if (buf.length >= 12 && buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  if (buf.slice(0, 5).toString('ascii') === '%PDF-') return 'application/pdf';
  return null;
}

// ---------- auth routes ----------
app.post('/api/login', (req, res) => {
  const ip = clientIp(req);
  if (tooManyAttempts(ip)) {
    return res.status(429).json({ error: 'too_many_attempts' });
  }
  const password = req.body && req.body.password;
  const expected = process.env.CLINIC_PASSWORD;
  if (!expected) {
    return res.status(500).json({ error: 'not_configured' });
  }
  const a = Buffer.from(String(password || ''));
  const b = Buffer.from(String(expected));
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!match) {
    recordFailure(ip);
    return res.status(401).json({ error: 'wrong_password' });
  }
  clearFailures(ip);
  setSessionCookie(req, res);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ authenticated: isAuthed(req), clinicName: process.env.CLINIC_NAME || 'عيادتي' });
});

// Everything under /api except the routes above requires a valid session.
app.use('/api', (req, res, next) => {
  if (req.path === '/login' || req.path === '/me') return next();
  requireAuth(req, res, next);
});

// ---------- patients ----------
app.get('/api/patients', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, phone, phone2, dob, gender, national_id, blood_type, allergies, archived, updated_at
       FROM patients ORDER BY name ASC`
    );
    res.json(rows);
  } catch (err) { serverError(res, err); }
});

app.post('/api/patients', async (req, res) => {
  try {
    const b = req.body || {};
    const name = str(b.name), phone = str(b.phone), dob = str(b.dob);
    if (!name || !phone) return bad(res, 'الاسم ورقم الهاتف مطلوبان');
    if (!dob || !isIsoDate(dob)) return bad(res, 'تاريخ الميلاد مطلوب');
    const id = crypto.randomUUID();
    const { rows } = await pool.query(
      `INSERT INTO patients (id, name, phone, phone2, email, dob, gender, national_id, blood_type, address, allergies, chronic_conditions, notes, archived)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,false) RETURNING *`,
      [id, name, phone, str(b.phone2), str(b.email), dob, str(b.gender), str(b.national_id),
       str(b.blood_type), str(b.address), str(b.allergies), str(b.chronic_conditions), str(b.notes)]
    );
    res.status(201).json(rows[0]);
  } catch (err) { serverError(res, err); }
});

app.get('/api/patients/:id', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  try {
    const { rows } = await pool.query(`SELECT * FROM patients WHERE id=$1`, [req.params.id]);
    if (!rows[0]) return notFound(res);
    res.json(rows[0]);
  } catch (err) { serverError(res, err); }
});

app.patch('/api/patients/:id', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  const b = req.body || {};
  const name = str(b.name), phone = str(b.phone), dob = str(b.dob);
  if (!name || !phone) return bad(res, 'الاسم ورقم الهاتف مطلوبان');
  if (!dob || !isIsoDate(dob)) return bad(res, 'تاريخ الميلاد مطلوب');
  try {
    const { rows } = await pool.query(
      `UPDATE patients SET name=$1, phone=$2, phone2=$3, email=$4, dob=$5, gender=$6, national_id=$7,
         blood_type=$8, address=$9, allergies=$10, chronic_conditions=$11, notes=$12, updated_at=now()
       WHERE id=$13 RETURNING *`,
      [name, phone, str(b.phone2), str(b.email), dob, str(b.gender), str(b.national_id),
       str(b.blood_type), str(b.address), str(b.allergies), str(b.chronic_conditions), str(b.notes), req.params.id]
    );
    if (!rows[0]) return notFound(res);
    res.json(rows[0]);
  } catch (err) { serverError(res, err); }
});

app.patch('/api/patients/:id/archive', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  const archived = !!(req.body && req.body.archived);
  try {
    const { rows } = await pool.query(
      `UPDATE patients SET archived=$1, updated_at=now() WHERE id=$2 RETURNING *`,
      [archived, req.params.id]
    );
    if (!rows[0]) return notFound(res);
    res.json(rows[0]);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/patients/:id', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  try {
    const { rowCount } = await pool.query(`DELETE FROM patients WHERE id=$1`, [req.params.id]);
    if (!rowCount) return notFound(res);
    res.json({ ok: true });
  } catch (err) { serverError(res, err); }
});

// ---------- visits ----------
app.get('/api/patients/:id/visits', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  try {
    const { rows } = await pool.query(
      `SELECT * FROM visits WHERE patient_id=$1 ORDER BY date DESC, created_at DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { serverError(res, err); }
});

app.post('/api/patients/:id/visits', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  const b = req.body || {};
  const date = str(b.date), reason = str(b.reason);
  if (!date || !reason) return bad(res, 'التاريخ وسبب الزيارة مطلوبان');
  const hasInsurance = !!b.has_insurance;
  try {
    const patient = await pool.query(`SELECT id FROM patients WHERE id=$1`, [req.params.id]);
    if (!patient.rows[0]) return notFound(res);
    const id = crypto.randomUUID();
    const { rows } = await pool.query(
      `INSERT INTO visits (id, patient_id, date, time, reason, diagnosis, treatment, doctor, notes, has_insurance, insurance_company)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [id, req.params.id, date, str(b.time), reason, str(b.diagnosis), str(b.treatment), str(b.doctor), str(b.notes),
       hasInsurance, hasInsurance ? str(b.insurance_company) : null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { serverError(res, err); }
});

app.patch('/api/patients/:id/visits/:vid', async (req, res) => {
  if (!isUuid(req.params.id) || !isUuid(req.params.vid)) return notFound(res);
  const b = req.body || {};
  const date = str(b.date), reason = str(b.reason);
  if (!date || !reason) return bad(res, 'التاريخ وسبب الزيارة مطلوبان');
  const hasInsurance = !!b.has_insurance;
  try {
    const { rows } = await pool.query(
      `UPDATE visits SET date=$1, time=$2, reason=$3, diagnosis=$4, treatment=$5, doctor=$6, notes=$7, has_insurance=$8, insurance_company=$9
       WHERE id=$10 AND patient_id=$11 RETURNING *`,
      [date, str(b.time), reason, str(b.diagnosis), str(b.treatment), str(b.doctor), str(b.notes),
       hasInsurance, hasInsurance ? str(b.insurance_company) : null, req.params.vid, req.params.id]
    );
    if (!rows[0]) return notFound(res);
    res.json(rows[0]);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/patients/:id/visits/:vid', async (req, res) => {
  if (!isUuid(req.params.id) || !isUuid(req.params.vid)) return notFound(res);
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM visits WHERE id=$1 AND patient_id=$2`, [req.params.vid, req.params.id]
    );
    if (!rowCount) return notFound(res);
    res.json({ ok: true });
  } catch (err) { serverError(res, err); }
});

// ---------- appointments ----------
const APPT_STATUSES = ['scheduled', 'done', 'cancelled', 'no_show'];

app.get('/api/appointments', async (req, res) => {
  const from = str(req.query.from), to = str(req.query.to);
  if (!from || !to || !isIsoDate(from) || !isIsoDate(to)) return bad(res, 'from و to مطلوبان (YYYY-MM-DD)');
  try {
    const { rows } = await pool.query(
      `SELECT * FROM appointments WHERE date BETWEEN $1 AND $2 ORDER BY date ASC, time ASC`,
      [from, to]
    );
    res.json(rows.map(apptOut));
  } catch (err) { serverError(res, err); }
});

async function resolveAppointmentPatient(b) {
  // Returns { patient_id, patient_name, phone } — either from a real linked
  // patient record, or a manually-typed "guest" name for someone not yet archived.
  const patientId = str(b.patient_id);
  if (patientId) {
    if (!isUuid(patientId)) return { error: 'مريض غير صالح' };
    const { rows } = await pool.query(`SELECT id, name, phone FROM patients WHERE id=$1`, [patientId]);
    if (!rows[0]) return { error: 'المريض غير موجود' };
    return { patient_id: rows[0].id, patient_name: rows[0].name, phone: rows[0].phone };
  }
  const name = str(b.patient_name);
  if (!name) return { error: 'اسم المريض مطلوب' };
  return { patient_id: null, patient_name: name, phone: str(b.phone) };
}

app.post('/api/appointments', async (req, res) => {
  const b = req.body || {};
  const date = str(b.date), time = str(b.time);
  if (!date || !isIsoDate(date) || !time) return bad(res, 'التاريخ والوقت مطلوبان');
  const who = await resolveAppointmentPatient(b);
  if (who.error) return bad(res, who.error);
  try {
    const id = crypto.randomUUID();
    const { rows } = await pool.query(
      `INSERT INTO appointments (id, patient_id, patient_name, phone, date, time, reason, doctor, status, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'scheduled',$9) RETURNING *`,
      [id, who.patient_id, who.patient_name, who.phone, date, time, str(b.reason), str(b.doctor), str(b.notes)]
    );
    res.status(201).json(apptOut(rows[0]));
  } catch (err) { serverError(res, err); }
});

app.patch('/api/appointments/:id', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  try {
    const existing = await pool.query(`SELECT * FROM appointments WHERE id=$1`, [req.params.id]);
    if (!existing.rows[0]) return notFound(res);
    const cur = existing.rows[0];
    const b = req.body || {};
    let patientId = cur.patient_id, patientName = cur.patient_name, phone = cur.phone;
    if (b.patient_id !== undefined || b.patient_name !== undefined) {
      const who = await resolveAppointmentPatient(b);
      if (who.error) return bad(res, who.error);
      patientId = who.patient_id; patientName = who.patient_name; phone = who.phone;
    }
    const date = b.date !== undefined ? str(b.date) : dateOnly(cur.date);
    const time = b.time !== undefined ? str(b.time) : cur.time;
    if (!date || !isIsoDate(date) || !time) return bad(res, 'التاريخ والوقت مطلوبان');
    const status = b.status !== undefined ? str(b.status) : cur.status;
    if (!APPT_STATUSES.includes(status)) return bad(res, 'حالة غير صالحة');
    const reason = b.reason !== undefined ? str(b.reason) : cur.reason;
    const doctor = b.doctor !== undefined ? str(b.doctor) : cur.doctor;
    const notes = b.notes !== undefined ? str(b.notes) : cur.notes;
    const { rows } = await pool.query(
      `UPDATE appointments SET patient_id=$1, patient_name=$2, phone=$3, date=$4, time=$5, reason=$6, doctor=$7, status=$8, notes=$9
       WHERE id=$10 RETURNING *`,
      [patientId, patientName, phone, date, time, reason, doctor, status, notes, req.params.id]
    );
    res.json(apptOut(rows[0]));
  } catch (err) { serverError(res, err); }
});

app.delete('/api/appointments/:id', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  try {
    const { rowCount } = await pool.query(`DELETE FROM appointments WHERE id=$1`, [req.params.id]);
    if (!rowCount) return notFound(res);
    res.json({ ok: true });
  } catch (err) { serverError(res, err); }
});

// ---------- attachments ----------
app.get('/api/patients/:id/attachments', async (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  try {
    const { rows } = await pool.query(
      `SELECT id, patient_id, filename, mime, size, note, uploaded_at FROM attachments
       WHERE patient_id=$1 ORDER BY uploaded_at DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { serverError(res, err); }
});

app.post('/api/patients/:id/attachments', (req, res) => {
  if (!isUuid(req.params.id)) return notFound(res);
  upload.single('file')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'الملف أكبر من الحد المسموح (6 ميغابايت)' : (err.message || 'تعذر رفع الملف');
      return bad(res, msg);
    }
    if (!req.file) return bad(res, 'لم يتم اختيار ملف');
    const sniffed = sniffMime(req.file.buffer);
    if (!sniffed || !ALLOWED_MIME.test(sniffed)) {
      return bad(res, 'محتوى الملف لا يطابق نوعه المُعلن — تأكد أنه صورة أو PDF فعلاً');
    }
    try {
      const patient = await pool.query(`SELECT id FROM patients WHERE id=$1`, [req.params.id]);
      if (!patient.rows[0]) return notFound(res);
      const id = crypto.randomUUID();
      const note = str(req.body && req.body.note);
      // Busboy (used by multer) decodes multipart filename headers as latin1 by
      // default, which corrupts non-ASCII (e.g. Arabic) filenames sent by real
      // browsers as UTF-8 bytes — re-decode to undo that.
      const rawName = req.file.originalname || 'مرفق';
      const filename = Buffer.from(rawName, 'latin1').toString('utf8').slice(0, 200);
      const { rows } = await pool.query(
        `INSERT INTO attachments (id, patient_id, filename, mime, data, size, note)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         RETURNING id, patient_id, filename, mime, size, note, uploaded_at`,
        [id, req.params.id, filename, sniffed, req.file.buffer, req.file.size, note]
      );
      res.status(201).json(rows[0]);
    } catch (e) { serverError(res, e); }
  });
});

app.get('/api/patients/:id/attachments/:aid/file', async (req, res) => {
  if (!isUuid(req.params.id) || !isUuid(req.params.aid)) return notFound(res);
  try {
    const { rows } = await pool.query(
      `SELECT filename, mime, data FROM attachments WHERE id=$1 AND patient_id=$2`,
      [req.params.aid, req.params.id]
    );
    if (!rows[0]) return notFound(res);
    const a = rows[0];
    res.set('Content-Type', a.mime);
    const disposition = req.query.download ? 'attachment' : 'inline';
    res.set('Content-Disposition', contentDisposition(disposition, a.filename));
    res.send(a.data);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/patients/:id/attachments/:aid', async (req, res) => {
  if (!isUuid(req.params.id) || !isUuid(req.params.aid)) return notFound(res);
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM attachments WHERE id=$1 AND patient_id=$2`, [req.params.aid, req.params.id]
    );
    if (!rowCount) return notFound(res);
    res.json({ ok: true });
  } catch (err) { serverError(res, err); }
});

// ---------- backup export ----------
app.get('/api/export', async (req, res) => {
  try {
    const patients = (await pool.query(`SELECT * FROM patients ORDER BY name ASC`)).rows;
    const visits = (await pool.query(`SELECT * FROM visits ORDER BY patient_id, date DESC`)).rows;
    const attachments = (await pool.query(
      `SELECT id, patient_id, filename, mime, size, note, uploaded_at FROM attachments ORDER BY patient_id, uploaded_at DESC`
    )).rows;
    const visitsByPatient = {}, attByPatient = {};
    visits.forEach(v => { (visitsByPatient[v.patient_id] ||= []).push(v); });
    attachments.forEach(a => { (attByPatient[a.patient_id] ||= []).push(a); });
    const out = {
      exported_at: new Date().toISOString(),
      note: 'ملفات المرفقات نفسها غير مضمّنة هنا (بيانات فقط) — نزّلها من داخل ملف كل مريض عند الحاجة.',
      patients: patients.map(p => ({ ...p, visits: visitsByPatient[p.id] || [], attachments: attByPatient[p.id] || [] })),
    };
    res.set('Content-Type', 'application/json; charset=utf-8');
    res.set('Content-Disposition', contentDisposition('attachment', `نسخة-احتياطية-${new Date().toISOString().slice(0,10)}.json`));
    res.send(JSON.stringify(out, null, 2));
  } catch (err) { serverError(res, err); }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.use((req, res) => res.status(404).json({ error: 'not_found' }));

migrate()
  .then(() => {
    app.listen(PORT, () => console.log('Clinic archive server running on port ' + PORT));
  })
  .catch((err) => {
    console.error('فشل إعداد قاعدة البيانات:', err);
    process.exit(1);
  });
