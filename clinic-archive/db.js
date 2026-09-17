const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL غير موجود. أضف قاعدة بيانات PostgreSQL وحدد رابطها في متغيرات البيئة.');
  process.exit(1);
}

// Railway's managed Postgres is reachable over a private network link without TLS,
// but some external/proxy connections need SSL. Allow self-signed certs either way.
const useSsl = process.env.PGSSL !== 'disable';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS patients (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      phone2 TEXT,
      email TEXT,
      dob DATE,
      gender TEXT,
      national_id TEXT,
      blood_type TEXT,
      address TEXT,
      allergies TEXT,
      chronic_conditions TEXT,
      notes TEXT,
      archived BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS visits (
      id UUID PRIMARY KEY,
      patient_id UUID NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      time TEXT,
      reason TEXT,
      diagnosis TEXT,
      treatment TEXT,
      doctor TEXT,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS attachments (
      id UUID PRIMARY KEY,
      patient_id UUID NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      filename TEXT NOT NULL,
      mime TEXT NOT NULL,
      data BYTEA NOT NULL,
      size INTEGER NOT NULL,
      note TEXT,
      uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_patients_archived ON patients(archived);
    CREATE INDEX IF NOT EXISTS idx_visits_patient ON visits(patient_id, date DESC);
    CREATE INDEX IF NOT EXISTS idx_attachments_patient ON attachments(patient_id, uploaded_at DESC);
  `);
}

module.exports = { pool, migrate };
