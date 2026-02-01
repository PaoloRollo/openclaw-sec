import Database from 'better-sqlite3';
import { Severity, Action } from '../types';

export interface SecurityEvent {
  id?: number;
  timestamp?: string;
  event_type: string;
  severity: Severity;
  action_taken: Action;
  user_id: string;
  session_id: string;
  input_text: string;
  patterns_matched: string;
  fingerprint: string;
  module: string;
  metadata: string;
}

export interface RateLimit {
  id?: number;
  user_id: string;
  window_start: string;
  request_count: number;
  blocked: number;
  last_updated?: string;
}

export interface UserReputation {
  id?: number;
  user_id: string;
  reputation_score: number;
  total_events: number;
  blocked_events: number;
  safe_events: number;
  first_seen?: string;
  last_seen?: string;
}

export interface AttackPattern {
  id?: number;
  pattern_hash: string;
  pattern_text: string;
  category: string;
  severity: Severity;
  first_seen?: string;
  last_seen?: string;
  occurrence_count: number;
  success_rate: number;
}

export interface NotificationLog {
  id?: number;
  timestamp?: string;
  event_id: number;
  channel: string;
  status: string;
  response_code?: number;
  error_message?: string;
}

export class DatabaseManager {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.initializeSchema();
  }

  private initializeSchema(): void {
    // Security Events Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        action_taken TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        input_text TEXT NOT NULL,
        patterns_matched TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        module TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
      );
    `);

    // Create indexes for security_events
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_events_user_id ON security_events(user_id);
      CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
      CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON security_events(fingerprint);
    `);

    // Rate Limits Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL UNIQUE,
        window_start DATETIME NOT NULL,
        request_count INTEGER DEFAULT 0,
        blocked INTEGER DEFAULT 0,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create indexes for rate_limits
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_rate_limits_user_id ON rate_limits(user_id);
      CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start ON rate_limits(window_start);
    `);

    // User Reputation Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_reputation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL UNIQUE,
        reputation_score REAL DEFAULT 100.0,
        total_events INTEGER DEFAULT 0,
        blocked_events INTEGER DEFAULT 0,
        safe_events INTEGER DEFAULT 0,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create indexes for user_reputation
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_reputation_user_id ON user_reputation(user_id);
      CREATE INDEX IF NOT EXISTS idx_reputation_score ON user_reputation(reputation_score);
    `);

    // Attack Patterns Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS attack_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_hash TEXT NOT NULL UNIQUE,
        pattern_text TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        occurrence_count INTEGER DEFAULT 1,
        success_rate REAL DEFAULT 0.0
      );
    `);

    // Create indexes for attack_patterns
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_patterns_hash ON attack_patterns(pattern_hash);
      CREATE INDEX IF NOT EXISTS idx_patterns_category ON attack_patterns(category);
      CREATE INDEX IF NOT EXISTS idx_patterns_severity ON attack_patterns(severity);
    `);

    // Notifications Log Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS notifications_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_id INTEGER NOT NULL,
        channel TEXT NOT NULL,
        status TEXT NOT NULL,
        response_code INTEGER,
        error_message TEXT,
        FOREIGN KEY (event_id) REFERENCES security_events(id)
      );
    `);

    // Create indexes for notifications_log
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_notifications_event_id ON notifications_log(event_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_timestamp ON notifications_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications_log(status);
    `);
  }

  public getTables(): string[] {
    const stmt = this.db.prepare(`
      SELECT name FROM sqlite_master
      WHERE type='table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `);
    const results = stmt.all() as Array<{ name: string }>;
    return results.map(row => row.name);
  }

  // Security Events Methods
  public insertEvent(event: SecurityEvent): number {
    const stmt = this.db.prepare(`
      INSERT INTO security_events (
        event_type, severity, action_taken, user_id, session_id,
        input_text, patterns_matched, fingerprint, module, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      event.event_type,
      event.severity,
      event.action_taken,
      event.user_id,
      event.session_id,
      event.input_text,
      event.patterns_matched,
      event.fingerprint,
      event.module,
      event.metadata
    );

    return result.lastInsertRowid as number;
  }

  public getEventById(id: number): SecurityEvent | undefined {
    const stmt = this.db.prepare('SELECT * FROM security_events WHERE id = ?');
    return stmt.get(id) as SecurityEvent | undefined;
  }

  public getEventsByUserId(userId: string, limit: number = 100): SecurityEvent[] {
    const stmt = this.db.prepare(`
      SELECT * FROM security_events
      WHERE user_id = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `);
    return stmt.all(userId, limit) as SecurityEvent[];
  }

  public getEventsBySeverity(severity: Severity, limit: number = 100): SecurityEvent[] {
    const stmt = this.db.prepare(`
      SELECT * FROM security_events
      WHERE severity = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `);
    return stmt.all(severity, limit) as SecurityEvent[];
  }

  // Rate Limits Methods
  public upsertRateLimit(rateLimit: RateLimit): number {
    const stmt = this.db.prepare(`
      INSERT INTO rate_limits (user_id, window_start, request_count, blocked)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        window_start = excluded.window_start,
        request_count = excluded.request_count,
        blocked = excluded.blocked,
        last_updated = CURRENT_TIMESTAMP
    `);

    const result = stmt.run(
      rateLimit.user_id,
      rateLimit.window_start,
      rateLimit.request_count,
      rateLimit.blocked
    );

    return result.lastInsertRowid as number;
  }

  public getRateLimitByUserId(userId: string): RateLimit | undefined {
    const stmt = this.db.prepare('SELECT * FROM rate_limits WHERE user_id = ?');
    return stmt.get(userId) as RateLimit | undefined;
  }

  // User Reputation Methods
  public upsertUserReputation(reputation: UserReputation): number {
    const stmt = this.db.prepare(`
      INSERT INTO user_reputation (
        user_id, reputation_score, total_events, blocked_events, safe_events
      )
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        reputation_score = excluded.reputation_score,
        total_events = excluded.total_events,
        blocked_events = excluded.blocked_events,
        safe_events = excluded.safe_events,
        last_seen = CURRENT_TIMESTAMP
    `);

    const result = stmt.run(
      reputation.user_id,
      reputation.reputation_score,
      reputation.total_events,
      reputation.blocked_events,
      reputation.safe_events
    );

    return result.lastInsertRowid as number;
  }

  public getUserReputation(userId: string): UserReputation | undefined {
    const stmt = this.db.prepare('SELECT * FROM user_reputation WHERE user_id = ?');
    return stmt.get(userId) as UserReputation | undefined;
  }

  // Attack Patterns Methods
  public upsertAttackPattern(pattern: AttackPattern): number {
    const stmt = this.db.prepare(`
      INSERT INTO attack_patterns (
        pattern_hash, pattern_text, category, severity, occurrence_count, success_rate
      )
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(pattern_hash) DO UPDATE SET
        last_seen = CURRENT_TIMESTAMP,
        occurrence_count = occurrence_count + 1,
        success_rate = excluded.success_rate
    `);

    const result = stmt.run(
      pattern.pattern_hash,
      pattern.pattern_text,
      pattern.category,
      pattern.severity,
      pattern.occurrence_count,
      pattern.success_rate
    );

    return result.lastInsertRowid as number;
  }

  public getAttackPatternByHash(hash: string): AttackPattern | undefined {
    const stmt = this.db.prepare('SELECT * FROM attack_patterns WHERE pattern_hash = ?');
    return stmt.get(hash) as AttackPattern | undefined;
  }

  public getAttackPatternsByCategory(category: string, limit: number = 100): AttackPattern[] {
    const stmt = this.db.prepare(`
      SELECT * FROM attack_patterns
      WHERE category = ?
      ORDER BY occurrence_count DESC
      LIMIT ?
    `);
    return stmt.all(category, limit) as AttackPattern[];
  }

  // Notifications Log Methods
  public insertNotificationLog(log: NotificationLog): number {
    const stmt = this.db.prepare(`
      INSERT INTO notifications_log (
        event_id, channel, status, response_code, error_message
      ) VALUES (?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      log.event_id,
      log.channel,
      log.status,
      log.response_code,
      log.error_message
    );

    return result.lastInsertRowid as number;
  }

  public getNotificationLogsByEventId(eventId: number): NotificationLog[] {
    const stmt = this.db.prepare('SELECT * FROM notifications_log WHERE event_id = ? ORDER BY timestamp DESC');
    return stmt.all(eventId) as NotificationLog[];
  }

  // Utility Methods
  public close(): void {
    this.db.close();
  }

  public vacuum(): void {
    this.db.exec('VACUUM');
  }

  public deleteOldEvents(daysToKeep: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM security_events
      WHERE timestamp < datetime('now', '-' || ? || ' days')
    `);
    const result = stmt.run(daysToKeep);
    return result.changes;
  }
}
