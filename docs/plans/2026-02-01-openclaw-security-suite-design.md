# OpenClaw Security Suite - Design Document

**Date:** 2026-02-01
**Status:** Approved for Implementation

## Overview

A comprehensive, enterprise-grade security suite for OpenClaw that combines prompt injection defense with runtime operation validation. Provides multi-language threat detection, real-time monitoring, and fine-grained user control.

## Goals

- Protect against prompt injection and manipulation attacks across multiple languages (EN/KO/JA/ZH)
- Validate runtime operations (commands, URLs, paths) before execution
- Provide real-time threat monitoring with configurable notifications
- Track user reputation and implement intelligent rate limiting
- Offer modular architecture with fine-grained configuration control

## Technology Stack

- **Language:** TypeScript
- **Runtime:** Node.js
- **Database:** SQLite for persistence and analytics
- **Architecture:** Modular with dependency injection
- **Integration:** OpenClaw skill with mandatory hooks

## Project Structure

```
openclaw-security/
├── SKILL.md              # OpenClaw skill definition
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts          # Main entry point
│   ├── cli.ts            # Skill command handler
│   ├── modules/          # All detection modules
│   │   ├── prompt-injection/
│   │   ├── command-validator/
│   │   ├── url-validator/
│   │   ├── path-validator/
│   │   ├── secret-detector/
│   │   └── content-scanner/
│   ├── core/
│   │   ├── severity-scorer.ts
│   │   ├── action-engine.ts
│   │   ├── database-manager.ts
│   │   ├── notification-system.ts
│   │   └── logger.ts
│   ├── patterns/         # Attack pattern definitions
│   │   ├── prompt-injection-patterns.ts
│   │   ├── command-patterns.ts
│   │   └── multilang-patterns.ts
│   └── types/            # TypeScript types
├── dist/                 # Compiled output
├── config.example.yaml
└── README.md
```

## Installation Paths

- Workspace: `<workspace>/skills/openclaw-security/`
- Global: `~/.openclaw/skills/openclaw-security/`
- Config: `~/.openclaw/openclaw-security/config.yaml`
- Database: `~/.openclaw/openclaw-security/security.db`
- Logs: `~/.openclaw/logs/security-events.log`

## Module Architecture

### Detection Modules

1. **PromptInjectionDetector** - Multi-language prompt injection detection
   - Instruction override patterns
   - Role manipulation
   - System impersonation
   - Jailbreak attempts
   - Scenario-based jailbreaks (dream, story, cinema, academic)
   - Emotional manipulation
   - Authority impersonation
   - Context hijacking
   - Multi-turn attacks
   - Token smuggling

2. **CommandValidator** - Shell command validation
   - Command injection patterns
   - Dangerous commands (rm -rf, dd, etc.)
   - Data exfiltration patterns
   - Pipe chains and metacharacters

3. **URLValidator** - URL safety validation
   - SSRF protection (private IPs, localhost)
   - Cloud metadata endpoints
   - Malicious URL patterns

4. **PathValidator** - File path validation
   - Path traversal detection
   - Sensitive file access (SSH keys, /etc/passwd, config files)

5. **SecretDetector** - Secret and credential detection
   - API keys (Anthropic, OpenAI, GitHub, AWS, 20+ services)
   - Token patterns
   - Credential leakage

6. **ContentScanner** - Obfuscation detection
   - Homoglyph detection
   - Base64 obfuscation
   - Unicode tricks
   - Token smuggling
   - Hidden characters

### Core Engine Modules

7. **SeverityScorer** - Severity analysis and scoring
   - Aggregates findings from all modules
   - Assigns severity: SAFE/LOW/MEDIUM/HIGH/CRITICAL

8. **ActionEngine** - Action determination
   - Maps severity to actions (allow/log/warn/block/block_notify)
   - Applies user configuration overrides
   - Considers user reputation

9. **DatabaseManager** - SQLite database operations
   - Event storage
   - Rate limiting
   - User reputation tracking
   - Analytics queries

10. **NotificationSystem** - Real-time alerting
    - Webhook notifications
    - Slack integration
    - Discord integration
    - Email alerts

11. **Logger** - Structured logging
    - Buffered writes
    - Log rotation
    - Retention policies

## Configuration System

Fine-grained YAML configuration at `~/.openclaw/openclaw-security/config.yaml`:

- Global sensitivity levels (paranoid/strict/medium/permissive)
- Per-module enable/disable
- Per-module sensitivity overrides
- Language selection
- Category-level control within modules
- Custom pattern support
- Action mapping per severity level
- Rate limiting configuration
- Notification channel setup
- Logging preferences
- Database settings

## Database Schema

### security_events
- Event history with timestamp, severity, action, user, patterns matched
- Indexed by timestamp, severity, user_id

### rate_limits
- Per-user request counting and lockout tracking

### user_reputation
- Trust scores (0-100)
- Total requests and blocked attempts
- Allowlist/blocklist flags

### attack_patterns
- Pattern definitions with usage statistics
- Custom pattern support

### notifications_log
- Notification delivery tracking

## Detection Flow

```
User Input / Tool Call
        ↓
Input Normalization (decode, normalize)
        ↓
Module Execution (parallel)
  ├─→ PromptInjection → Findings[]
  ├─→ CommandValidator → Findings[]
  ├─→ URLValidator → Findings[]
  ├─→ PathValidator → Findings[]
  ├─→ SecretDetector → Findings[]
  └─→ ContentScanner → Findings[]
        ↓
Severity Scoring (aggregate findings)
        ↓
Rate Limit & Reputation Check
        ↓
Action Engine (determine action)
        ↓
Return Result IMMEDIATELY (~20-50ms)
        ↓
Fire-and-forget Async:
  ├─→ Database Write (queued, batched)
  ├─→ Notifications (async)
  └─→ Log File Write (buffered)
```

## Performance Targets

- Validation response: ~20-50ms (synchronous)
- Database writes: async, batched every 100ms or 50 events
- No blocking on I/O operations
- Buffer overflow protection (max 10k queued events)

## OpenClaw Integration

### Skill Commands

All commands invoked with `/openclaw-sec <command>`:

**Validation:**
- `validate-command <cmd>` - Check command safety
- `check-url <url>` - Validate URL
- `validate-path <path>` - Check path
- `scan-content <text>` - Scan for injection
- `check-all` - Run all validators

**Monitoring:**
- `events [--last <time>] [--severity <level>]` - Show events
- `stats` - Statistics dashboard
- `analyze [--since <date>] [--group-by <field>]` - Analytics
- `reputation --user <id>` - User trust score
- `watch` - Real-time event stream

**Management:**
- `config` - Show configuration
- `config set <key> <value>` - Update config
- `test --category <type>` - Test detection
- `report --format <fmt>` - Export report
- `db vacuum` - Database maintenance

### Hook Integration (Mandatory)

**user-prompt-submit-hook:**
- Intercepts user input before model processing
- Scans for prompt injection
- Blocks at HIGH/CRITICAL severity

**tool-call-hook:**
- Validates operations before execution
- Command validation before Bash tool
- URL checking before WebFetch
- Path validation before Read/Write/Edit

## Severity Levels & Actions

- **SAFE** ✅ - Allow, no action
- **LOW** 📝 - Allow + log silently
- **MEDIUM** ⚠️ - Allow + log + warn user
- **HIGH** 🔴 - Block + log + show error
- **CRITICAL** 🚨 - Block + log + notify + potential lockout

## Pattern Organization

Patterns organized by category with metadata:
- Pattern ID, category, subcategory
- Regex pattern
- Severity level
- Language (en/ko/ja/zh/all)
- Description and examples
- False positive risk assessment
- Enable/disable flag
- Tags for filtering

## Testing Strategy

- Unit tests for each module
- Integration tests for detection flow
- Known attack vector test suite
- Performance benchmarking
- False positive/negative testing
- Multi-language validation

## Security Considerations

- No secrets in logs or database
- Sanitize user input in output
- Rate limiting to prevent DoS
- Database encryption at rest (optional)
- Secure notification webhooks (HTTPS only)
- Input validation on all CLI commands

## Future Enhancements

- Machine learning-based anomaly detection
- Integration with external threat intelligence feeds
- Advanced forensics and investigation tools
- Multi-tenant support with isolation
- Plugin system for custom detectors
- Web dashboard for visualization

## Success Criteria

- Detection response time < 50ms for 95th percentile
- False positive rate < 1%
- Zero false negatives on known attack vectors
- Successful integration with OpenClaw hooks
- Complete multi-language coverage (EN/KO/JA/ZH)
- User satisfaction with configuration flexibility

---

**Design approved and ready for implementation.**
