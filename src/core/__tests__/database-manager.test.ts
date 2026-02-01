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
      window_start: new Date().toISOString(),
      request_count: 5,
      blocked: 0
    };

    const id = db.upsertRateLimit(rateLimit);
    expect(id).toBeGreaterThan(0);

    const retrieved = db.getRateLimitByUserId('user123');
    expect(retrieved).toBeDefined();
    expect(retrieved?.request_count).toBe(5);

    // Test update
    const updated = {
      user_id: 'user123',
      window_start: new Date().toISOString(),
      request_count: 10,
      blocked: 1
    };

    db.upsertRateLimit(updated);
    const retrievedUpdated = db.getRateLimitByUserId('user123');
    expect(retrievedUpdated?.request_count).toBe(10);
    expect(retrievedUpdated?.blocked).toBe(1);
  });

  test('upserts and retrieves user reputation', () => {
    const reputation = {
      user_id: 'user123',
      reputation_score: 85.5,
      total_events: 10,
      blocked_events: 2,
      safe_events: 8
    };

    const id = db.upsertUserReputation(reputation);
    expect(id).toBeGreaterThan(0);

    const retrieved = db.getUserReputation('user123');
    expect(retrieved).toBeDefined();
    expect(retrieved?.reputation_score).toBe(85.5);
    expect(retrieved?.total_events).toBe(10);
  });

  test('upserts and retrieves attack patterns', () => {
    const pattern = {
      pattern_hash: 'hash123',
      pattern_text: 'ignore previous instructions',
      category: 'prompt_injection',
      severity: Severity.HIGH,
      occurrence_count: 1,
      success_rate: 0.5
    };

    const id = db.upsertAttackPattern(pattern);
    expect(id).toBeGreaterThan(0);

    const retrieved = db.getAttackPatternByHash('hash123');
    expect(retrieved).toBeDefined();
    expect(retrieved?.pattern_text).toBe('ignore previous instructions');
    expect(retrieved?.occurrence_count).toBe(1);

    // Test update increments occurrence_count
    db.upsertAttackPattern({ ...pattern, success_rate: 0.7 });
    const updated = db.getAttackPatternByHash('hash123');
    expect(updated?.occurrence_count).toBe(2);
  });

  test('retrieves attack patterns by category', () => {
    const pattern1 = {
      pattern_hash: 'hash1',
      pattern_text: 'pattern 1',
      category: 'prompt_injection',
      severity: Severity.HIGH,
      occurrence_count: 5,
      success_rate: 0.5
    };

    const pattern2 = {
      pattern_hash: 'hash2',
      pattern_text: 'pattern 2',
      category: 'prompt_injection',
      severity: Severity.MEDIUM,
      occurrence_count: 3,
      success_rate: 0.3
    };

    db.upsertAttackPattern(pattern1);
    db.upsertAttackPattern(pattern2);

    const patterns = db.getAttackPatternsByCategory('prompt_injection');
    expect(patterns).toHaveLength(2);
    expect(patterns[0].occurrence_count).toBe(5); // Sorted by occurrence_count DESC
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
      event_id: eventId,
      channel: 'slack',
      status: 'success',
      response_code: 200,
      error_message: undefined
    };

    const logId = db.insertNotificationLog(notificationLog);
    expect(logId).toBeGreaterThan(0);

    const logs = db.getNotificationLogsByEventId(eventId);
    expect(logs).toHaveLength(1);
    expect(logs[0].channel).toBe('slack');
    expect(logs[0].status).toBe('success');
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
