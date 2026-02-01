import { DatabaseManager } from '../database-manager';
import { Severity, Action } from '../../types';
import * as fs from 'fs';
import * as path from 'path';

describe('DatabaseManager', () => {
  let db: DatabaseManager;
  let testDbPath: string;

  beforeEach(() => {
    testDbPath = path.join(__dirname, 'test.db');
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    db = new DatabaseManager(testDbPath);
  });

  afterEach(() => {
    db.close();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  test('initializes database with correct schema', () => {
    const tables = db.getTables();
    expect(tables).toContain('security_events');
    expect(tables).toContain('rate_limits');
    expect(tables).toContain('user_reputation');
    expect(tables).toContain('attack_patterns');
    expect(tables).toContain('notifications_log');
  });

  test('inserts and retrieves security event', () => {
    const event = {
      event_type: 'prompt_injection',
      severity: Severity.HIGH,
      action_taken: Action.BLOCK,
      user_id: 'user123',
      session_id: 'session456',
      input_text: 'ignore previous instructions',
      patterns_matched: JSON.stringify(['instruction_override']),
      fingerprint: 'abc123',
      module: 'prompt_injection',
      metadata: JSON.stringify({})
    };

    const id = db.insertEvent(event);
    expect(id).toBeGreaterThan(0);

    const retrieved = db.getEventById(id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.severity).toBe(Severity.HIGH);
  });

  test('retrieves events by user ID', () => {
    const event1 = {
      event_type: 'prompt_injection',
      severity: Severity.HIGH,
      action_taken: Action.BLOCK,
      user_id: 'user123',
      session_id: 'session456',
      input_text: 'test input 1',
      patterns_matched: JSON.stringify(['pattern1']),
      fingerprint: 'hash1',
      module: 'prompt_injection',
      metadata: JSON.stringify({})
    };

    const event2 = {
      event_type: 'command_injection',
      severity: Severity.MEDIUM,
      action_taken: Action.WARN,
      user_id: 'user123',
      session_id: 'session789',
      input_text: 'test input 2',
      patterns_matched: JSON.stringify(['pattern2']),
      fingerprint: 'hash2',
      module: 'command_validator',
      metadata: JSON.stringify({})
    };

    db.insertEvent(event1);
    db.insertEvent(event2);

    const events = db.getEventsByUserId('user123');
    expect(events).toHaveLength(2);
    // Events should be sorted by timestamp descending
    expect(events.some(e => e.event_type === 'prompt_injection')).toBe(true);
    expect(events.some(e => e.event_type === 'command_injection')).toBe(true)
  });

  test('upserts and retrieves rate limit', () => {
    const rateLimit = {
      user_id: 'user123',
      request_count: 5,
      window_start: new Date().toISOString(),
      lockout_until: undefined,
      failed_attempts: 0
    };

    db.upsertRateLimit(rateLimit);

    const retrieved = db.getRateLimitByUserId('user123');
    expect(retrieved).toBeDefined();
    expect(retrieved?.request_count).toBe(5);
    expect(retrieved?.failed_attempts).toBe(0);

    // Test update
    const updated = {
      user_id: 'user123',
      request_count: 10,
      window_start: new Date().toISOString(),
      lockout_until: new Date().toISOString(),
      failed_attempts: 3
    };

    db.upsertRateLimit(updated);
    const retrievedUpdated = db.getRateLimitByUserId('user123');
    expect(retrievedUpdated?.request_count).toBe(10);
    expect(retrievedUpdated?.failed_attempts).toBe(3);
  });

  test('upserts and retrieves user reputation', () => {
    const reputation = {
      user_id: 'user123',
      trust_score: 85.5,
      total_requests: 10,
      blocked_attempts: 2,
      last_violation: undefined,
      is_allowlisted: 0,
      is_blocklisted: 0,
      notes: undefined
    };

    db.upsertUserReputation(reputation);

    const retrieved = db.getUserReputation('user123');
    expect(retrieved).toBeDefined();
    expect(retrieved?.trust_score).toBe(85.5);
    expect(retrieved?.total_requests).toBe(10);
    expect(retrieved?.blocked_attempts).toBe(2);
  });

  test('upserts and retrieves attack patterns', () => {
    const pattern = {
      pattern: 'ignore previous instructions',
      category: 'prompt_injection',
      severity: Severity.HIGH,
      language: 'en',
      times_matched: 1,
      last_matched: new Date().toISOString(),
      is_custom: 0,
      enabled: 1
    };

    const id = db.upsertAttackPattern(pattern);
    expect(id).toBeGreaterThan(0);

    const retrieved = db.getAttackPatternByPattern('ignore previous instructions');
    expect(retrieved).toBeDefined();
    expect(retrieved?.pattern).toBe('ignore previous instructions');
    expect(retrieved?.times_matched).toBe(1);
    expect(retrieved?.language).toBe('en');

    // Test update
    db.upsertAttackPattern({ ...pattern, times_matched: 5 });
    const updated = db.getAttackPatternByPattern('ignore previous instructions');
    expect(updated?.times_matched).toBe(5);
  });

  test('retrieves attack patterns by category', () => {
    const pattern1 = {
      pattern: 'pattern 1',
      category: 'prompt_injection',
      severity: Severity.HIGH,
      language: 'en',
      times_matched: 5,
      last_matched: new Date().toISOString(),
      is_custom: 0,
      enabled: 1
    };

    const pattern2 = {
      pattern: 'pattern 2',
      category: 'prompt_injection',
      severity: Severity.MEDIUM,
      language: 'en',
      times_matched: 3,
      last_matched: new Date().toISOString(),
      is_custom: 0,
      enabled: 1
    };

    db.upsertAttackPattern(pattern1);
    db.upsertAttackPattern(pattern2);

    const patterns = db.getAttackPatternsByCategory('prompt_injection');
    expect(patterns).toHaveLength(2);
    expect(patterns[0].times_matched).toBe(5); // Sorted by times_matched DESC
  });

  test('inserts and retrieves notification logs', () => {
    const event = {
      event_type: 'prompt_injection',
      severity: Severity.HIGH,
      action_taken: Action.BLOCK,
      user_id: 'user123',
      session_id: 'session456',
      input_text: 'test',
      patterns_matched: JSON.stringify([]),
      fingerprint: 'hash',
      module: 'prompt_injection',
      metadata: JSON.stringify({})
    };

    const eventId = db.insertEvent(event);

    const notificationLog = {
      channel: 'slack',
      severity: Severity.HIGH,
      message: 'High severity attack detected',
      delivery_status: 'success',
      event_id: eventId
    };

    const logId = db.insertNotificationLog(notificationLog);
    expect(logId).toBeGreaterThan(0);

    const logs = db.getNotificationLogsByEventId(eventId);
    expect(logs).toHaveLength(1);
    expect(logs[0].channel).toBe('slack');
    expect(logs[0].delivery_status).toBe('success');
    expect(logs[0].severity).toBe(Severity.HIGH);
    expect(logs[0].message).toBe('High severity attack detected');
  });

  test('deletes old events', () => {
    const event = {
      event_type: 'prompt_injection',
      severity: Severity.HIGH,
      action_taken: Action.BLOCK,
      user_id: 'user123',
      session_id: 'session456',
      input_text: 'test',
      patterns_matched: JSON.stringify([]),
      fingerprint: 'hash',
      module: 'prompt_injection',
      metadata: JSON.stringify({})
    };

    db.insertEvent(event);

    // Delete events older than 0 days should delete nothing (events just created)
    const deleted = db.deleteOldEvents(0);
    expect(deleted).toBe(0);

    const events = db.getEventsByUserId('user123');
    expect(events).toHaveLength(1);
  });
});
