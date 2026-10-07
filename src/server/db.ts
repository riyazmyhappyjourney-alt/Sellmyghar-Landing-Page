import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

const DB_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

const DB_PATH = path.join(DB_DIR, 'leads.db');
export const db = new DatabaseSync(DB_PATH);

// Initialize database schema with constraints, safe types, and indexes
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;

  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    source_intent TEXT,
    quality_score TEXT NOT NULL,
    quality_points INTEGER NOT NULL,
    quality_reasons TEXT,
    ip_address TEXT,
    user_agent TEXT,
    submission_time_ms INTEGER,
    submission_count INTEGER NOT NULL DEFAULT 1,
    is_duplicate INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_leads_phone ON leads(phone);
  CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);
  CREATE INDEX IF NOT EXISTS idx_leads_created_at ON leads(created_at);
  CREATE INDEX IF NOT EXISTS idx_leads_ip ON leads(ip_address);
`);

export interface StoredLead {
  id?: number;
  name: string;
  phone: string;
  email: string;
  source_intent: string;
  quality_score: 'HIGH_QUALITY' | 'NORMAL' | 'SUSPICIOUS' | 'SPAM';
  quality_points: number;
  quality_reasons: string;
  ip_address: string;
  user_agent: string;
  submission_time_ms: number;
  submission_count: number;
  is_duplicate: number;
  created_at: string;
  updated_at: string;
}

const insertStmt = db.prepare(`
  INSERT INTO leads (
    name, phone, email, source_intent, quality_score, quality_points,
    quality_reasons, ip_address, user_agent, submission_time_ms,
    submission_count, is_duplicate, created_at, updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const findRecentDuplicateStmt = db.prepare(`
  SELECT id, submission_count FROM leads 
  WHERE (phone = ? OR email = ?) AND created_at >= ?
  ORDER BY id DESC LIMIT 1
`);

const updateDuplicateStmt = db.prepare(`
  UPDATE leads 
  SET submission_count = submission_count + 1,
      source_intent = ?,
      updated_at = ?
  WHERE id = ?
`);

export function findRecentLead(phone: string, email: string, sinceIsoString: string) {
  try {
    return findRecentDuplicateStmt.get(phone, email, sinceIsoString) as { id: number; submission_count: number } | undefined;
  } catch (err) {
    console.error('Database query error:', err);
    return undefined;
  }
}

export function updateDuplicateLead(id: number, sourceIntent: string, updatedIsoString: string) {
  try {
    updateDuplicateStmt.run(sourceIntent, updatedIsoString, id);
    return true;
  } catch (err) {
    console.error('Database update error:', err);
    return false;
  }
}

export function insertLead(lead: StoredLead): number {
  const result = insertStmt.run(
    lead.name,
    lead.phone,
    lead.email,
    lead.source_intent,
    lead.quality_score,
    lead.quality_points,
    lead.quality_reasons,
    lead.ip_address,
    lead.user_agent,
    lead.submission_time_ms,
    lead.submission_count,
    lead.is_duplicate,
    lead.created_at,
    lead.updated_at
  );
  return Number(result.lastInsertRowid);
}
