import 'dotenv/config';
import { query, pool } from './db.js';

async function migrate() {
  console.log('Running database migrations...');

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(256) UNIQUE NOT NULL,
      password_hash VARCHAR(256),
      name VARCHAR(256) NOT NULL,
      role VARCHAR(32) DEFAULT 'user',
      stripe_customer_id VARCHAR(128),
      trial_expiry TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('Created table: users');

  await query(`
    CREATE TABLE IF NOT EXISTS simulations (
      id SERIAL PRIMARY KEY,
      request_id VARCHAR(64) UNIQUE NOT NULL,
      user_email VARCHAR(256),
      particle_id VARCHAR(128),
      material VARCHAR(128),
      core_size FLOAT,
      zeta_potential FLOAT,
      surface_area FLOAT,
      bandgap_energy FLOAT,
      dosage FLOAT,
      exposure_time FLOAT,
      env_ph FLOAT,
      protein_corona BOOLEAN,
      aggregation_factor FLOAT,
      hydrodynamic_diameter FLOAT,
      zeta_shift FLOAT,
      toxicity_result VARCHAR(32),
      confidence FLOAT,
      risk_score FLOAT,
      ros_generation FLOAT,
      apoptosis_likelihood FLOAT,
      necrosis_likelihood FLOAT,
      primary_pathway TEXT,
      explanation TEXT,
      raw_response JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('Created table: simulations');

  await query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id SERIAL PRIMARY KEY,
      user_email VARCHAR(256) NOT NULL,
      key_hash VARCHAR(256) UNIQUE NOT NULL,
      key_prefix VARCHAR(12) NOT NULL,
      name VARCHAR(128),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_used_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ
    );
  `);
  console.log('Created table: api_keys');

  await query(`
    CREATE TABLE IF NOT EXISTS batch_jobs (
      id SERIAL PRIMARY KEY,
      job_id VARCHAR(64) UNIQUE NOT NULL,
      user_email VARCHAR(256),
      status VARCHAR(32) DEFAULT 'pending',
      total_rows INTEGER DEFAULT 0,
      completed_rows INTEGER DEFAULT 0,
      result_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      completed_at TIMESTAMPTZ
    );
  `);
  console.log('Created table: batch_jobs');

  await query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      user_email VARCHAR(256),
      action VARCHAR(128),
      details JSONB,
      ip_address VARCHAR(64),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('Created table: audit_logs');

  console.log('All migrations completed successfully.');
  await pool.end();
}

migrate().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
