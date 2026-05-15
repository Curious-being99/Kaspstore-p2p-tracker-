import Database from 'better-sqlite3';
import path from 'path';

// Use a persistent file
const db = new Database(path.join(process.cwd(), 'tracker.db'));

// Ensure tables exist
db.exec(`
  CREATE TABLE IF NOT EXISTS verified_peers (
    peerId TEXT PRIMARY KEY,
    publicKey TEXT,
    lastSeen INTEGER,
    ip TEXT,
    trustScore REAL DEFAULT 0.0
  );
  
  CREATE TABLE IF NOT EXISTS dag_blocks (
    hash TEXT PRIMARY KEY,
    data TEXT
  );

  CREATE TABLE IF NOT EXISTS search_trackers (
    queryHash TEXT PRIMARY KEY,
    data TEXT
  );
`);

export default db;
