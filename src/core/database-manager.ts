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
  user_id: string;
  request_count: number;
  window_start: string;
  lockout_until?: string;
  failed_attempts: number;
}

export interface UserReputation {
  user_id: string;
  trust_score: number;
  total_requests: number;
  blocked_attempts: number;
  last_violation?: string;
  is_allowlisted: number;
  is_blocklisted: number;
  notes?: string;
}

export interface AttackPattern {
  id?: number;
  pattern: string;
  category: string;
  severity: Severity;
  language: string;
  times_matched: number;
  last_matched?: string;
  is_custom: number;
  enabled: number;
}

export interface NotificationLog {
  id?: number;
  timestamp?: string;
  channel: string;
  severity: Severity;
  message: string;
  delivery_status: string;
  event_id: number;
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
        user_id TEXT PRIMARY KEY,
        request_count INTEGER DEFAULT 0,
        window_start DATETIME NOT NULL,
        lockout_until DATETIME,
        failed_attempts INTEGER DEFAULT 0
      );
    `);

    // Create indexes for rate_limits
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start ON rate_limits(window_start);
    `);

    // User Reputation Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_reputation (
        user_id TEXT PRIMARY KEY,
        trust_score REAL DEFAULT 100.0,
        total_requests INTEGER DEFAULT 0,
        blocked_attempts INTEGER DEFAULT 0,
        last_violation DATETIME,
        is_allowlisted INTEGER DEFAULT 0,
        is_blocklisted INTEGER DEFAULT 0,
        notes TEXT
      );
    `);

    // Create indexes for user_reputation
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_reputation_trust_score ON user_reputation(trust_score);
    `);

    // Attack Patterns Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS attack_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT NOT NULL UNIQUE,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        language TEXT NOT NULL,
        times_matched INTEGER DEFAULT 0,
        last_matched DATETIME,
        is_custom INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1
      );
    `);

    // Create indexes for attack_patterns
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_patterns_pattern ON attack_patterns(pattern);
      CREATE INDEX IF NOT EXISTS idx_patterns_category ON attack_patterns(category);
      CREATE INDEX IF NOT EXISTS idx_patterns_severity ON attack_patterns(severity);
    `);

    // Notifications Log Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS notifications_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        channel TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        delivery_status TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        FOREIGN KEY (event_id) REFERENCES security_events(id)
      );
    `);

    // Create indexes for notifications_log
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_notifications_event_id ON notifications_log(event_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_timestamp ON notifications_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_notifications_delivery_status ON notifications_log(delivery_status);
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
  public upsertRateLimit(rateLimit: RateLimit): void {
    const stmt = this.db.prepare(`
      INSERT INTO rate_limits (user_id, request_count, window_start, lockout_until, failed_attempts)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        request_count = excluded.request_count,
        window_start = excluded.window_start,
        lockout_until = excluded.lockout_until,
        failed_attempts = excluded.failed_attempts
    `);

    stmt.run(
      rateLimit.user_id,
      rateLimit.request_count,
      rateLimit.window_start,
      rateLimit.lockout_until,
      rateLimit.failed_attempts
    );
  }

  public getRateLimitByUserId(userId: string): RateLimit | undefined {
    const stmt = this.db.prepare('SELECT * FROM rate_limits WHERE user_id = ?');
    return stmt.get(userId) as RateLimit | undefined;
  }

  // User Reputation Methods
  public upsertUserReputation(reputation: UserReputation): void {
    const stmt = this.db.prepare(`
      INSERT INTO user_reputation (
        user_id, trust_score, total_requests, blocked_attempts, last_violation, is_allowlisted, is_blocklisted, notes
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        trust_score = excluded.trust_score,
        total_requests = excluded.total_requests,
        blocked_attempts = excluded.blocked_attempts,
        last_violation = excluded.last_violation,
        is_allowlisted = excluded.is_allowlisted,
        is_blocklisted = excluded.is_blocklisted,
        notes = excluded.notes
    `);

    stmt.run(
      reputation.user_id,
      reputation.trust_score,
      reputation.total_requests,
      reputation.blocked_attempts,
      reputation.last_violation,
      reputation.is_allowlisted,
      reputation.is_blocklisted,
      reputation.notes
    );
  }

  public getUserReputation(userId: string): UserReputation | undefined {
    const stmt = this.db.prepare('SELECT * FROM user_reputation WHERE user_id = ?');
    return stmt.get(userId) as UserReputation | undefined;
  }

  // Attack Patterns Methods
  public upsertAttackPattern(pattern: AttackPattern): number {
    const stmt = this.db.prepare(`
      INSERT INTO attack_patterns (
        pattern, category, severity, language, times_matched, last_matched, is_custom, enabled
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(pattern) DO UPDATE SET
        category = excluded.category,
        severity = excluded.severity,
        language = excluded.language,
        times_matched = excluded.times_matched,
        last_matched = excluded.last_matched,
        is_custom = excluded.is_custom,
        enabled = excluded.enabled
    `);

    const result = stmt.run(
      pattern.pattern,
      pattern.category,
      pattern.severity,
      pattern.language,
      pattern.times_matched,
      pattern.last_matched,
      pattern.is_custom,
      pattern.enabled
    );

    return result.lastInsertRowid as number;
  }

  public getAttackPatternByPattern(pattern: string): AttackPattern | undefined {
    const stmt = this.db.prepare('SELECT * FROM attack_patterns WHERE pattern = ?');
    return stmt.get(pattern) as AttackPattern | undefined;
  }

  public getAttackPatternsByCategory(category: string, limit: number = 100): AttackPattern[] {
    const stmt = this.db.prepare(`
      SELECT * FROM attack_patterns
      WHERE category = ?
      ORDER BY times_matched DESC
      LIMIT ?
    `);
    return stmt.all(category, limit) as AttackPattern[];
  }

  // Notifications Log Methods
  public insertNotificationLog(log: NotificationLog): number {
    const stmt = this.db.prepare(`
      INSERT INTO notifications_log (
        channel, severity, message, delivery_status, event_id
      ) VALUES (?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      log.channel,
      log.severity,
      log.message,
      log.delivery_status,
      log.event_id
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
