# OpenClaw Security Hooks

Automated security validation hooks for Claude Code and other AI agent platforms.

## Overview

OpenClaw Security Hooks provide **automatic, real-time protection** for AI agent interactions by intercepting and validating:

- **User Input** (before submission to the agent)
- **Tool Calls** (before execution)

## Available Hooks

### 1. User Prompt Submit Hook

**File:** `user-prompt-submit-hook.ts`

**Purpose:** Validates user input before it's submitted to the AI agent.

**Detects:**
- Prompt injection attempts
- Command injection patterns
- Malicious URLs
- Path traversal attempts
- Exposed secrets
- Obfuscation techniques

**Actions:**
- ✅ **ALLOW** - Safe input, proceed normally
- ⚠️  **WARN** - Potential issues, allow but log
- 🚫 **BLOCK** - Security threat detected, reject input

### 2. Tool Call Hook

**File:** `tool-call-hook.ts`

**Purpose:** Validates tool/function call parameters before execution.

**Validates:**
- Shell command parameters (Bash, exec)
- File path parameters (Read, Write, Edit)
- URL parameters (WebFetch, curl, wget)
- Content parameters

**Protected Tools:**
- `bash`, `exec` - Command injection validation
- `read`, `write`, `edit` - Path traversal validation
- `web_fetch`, `curl`, `wget` - SSRF validation

## Installation

### Automatic Installation

Run the installation script:

```bash
cd hooks/
./install-hooks.sh
```

This will:
1. Create `~/.claude-code/hooks/` directory
2. Copy hook files to the hooks directory
3. Make hooks executable
4. Create symlinks to the OpenClaw codebase

### Manual Installation

1. **Create hooks directory:**
   ```bash
   mkdir -p ~/.claude-code/hooks
   ```

2. **Copy hook files:**
   ```bash
   cp user-prompt-submit-hook.ts ~/.claude-code/hooks/
   cp tool-call-hook.ts ~/.claude-code/hooks/
   ```

3. **Make executable:**
   ```bash
   chmod +x ~/.claude-code/hooks/*.ts
   ```

4. **Create symlink to OpenClaw:**
   ```bash
   ln -s /path/to/openclaw-sec ~/.claude-code/hooks/openclaw-sec
   ```

## Configuration

Hooks use the same configuration as the OpenClaw Security Suite.

### Config File Locations (in priority order):

1. `./openclaw-security.yaml` (current directory)
2. `~/.openclaw/security-config.yaml` (home directory)
3. Default configuration (if no file found)

### Example Configuration

Create `.openclaw-security.yaml`:

```yaml
openclaw_security:
  enabled: true
  sensitivity: medium  # paranoid | strict | medium | permissive

  modules:
    prompt_injection:
      enabled: true
    command_validator:
      enabled: true
    url_validator:
      enabled: true
    path_validator:
      enabled: true
    secret_detector:
      enabled: true
    content_scanner:
      enabled: true

  actions:
    SAFE: allow
    LOW: log
    MEDIUM: warn
    HIGH: block
    CRITICAL: block_notify

  database:
    path: .openclaw-security.db
    analytics_enabled: true
    retention_days: 365

  logging:
    enabled: true
    level: info
    file: ~/.openclaw/logs/security-events.log
```

## Testing Hooks

### Test User Prompt Hook

```bash
echo '{"userPrompt":"rm -rf /","userId":"test-user","sessionId":"test-123"}' | \
  node ~/.claude-code/hooks/user-prompt-submit-hook.ts
```

Expected output for malicious input:
```json
{
  "allow": false,
  "severity": "HIGH",
  "message": "🚫 Security Warning: This input has been blocked...",
  "findings": [...]
}
```

### Test Tool Call Hook

```bash
echo '{
  "toolName": "bash",
  "parameters": [
    {"name": "command", "value": "ls -la"}
  ],
  "userId": "test-user",
  "sessionId": "test-123"
}' | node ~/.claude-code/hooks/tool-call-hook.ts
```

## Hook Behavior

### User Prompt Submit Hook

```
┌─────────────────┐
│   User Input    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Security Scan  │ ← All 6 modules run in parallel
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │Action? │
    └───┬────┘
        │
    ┌───┴───┬──────────┬────────┐
    ▼       ▼          ▼        ▼
  ALLOW   LOG/WARN   BLOCK   BLOCK_NOTIFY
    │       │          │        │
    ▼       ▼          ▼        ▼
 Submit  Submit +   Reject    Reject +
         Warning   + Message  Notify
```

### Tool Call Hook

```
┌─────────────────┐
│   Tool Call     │
│  (with params)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Extract & Scan  │ ← Validate relevant parameters
│   Parameters    │
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │Action? │
    └───┬────┘
        │
    ┌───┴───┬──────┐
    ▼       ▼      ▼
  ALLOW   WARN   BLOCK
    │       │      │
    ▼       ▼      ▼
 Execute  Execute Reject
         + Log   + Message
```

## Performance

- **Validation Time:** ~20-50ms per check
- **Async Writes:** Database writes don't block validation
- **Parallel Scanning:** All modules run concurrently
- **Minimal Overhead:** Negligible impact on user experience

## Security Events

All validations are logged to the database:

```bash
# View recent events
openclaw-sec events --limit 50

# View events for specific user
openclaw-sec events --user-id "alice@example.com"

# View high-severity events
openclaw-sec events --severity HIGH
```

## Troubleshooting

### Hooks not running?

1. Check hooks directory:
   ```bash
   ls -la ~/.claude-code/hooks/
   ```

2. Verify hooks are executable:
   ```bash
   chmod +x ~/.claude-code/hooks/*.ts
   ```

3. Check symlink:
   ```bash
   ls -la ~/.claude-code/hooks/openclaw-sec
   ```

### Hooks failing silently?

Hooks fail-open by default (allow on error) to prevent breaking the workflow.

Check logs:
```bash
tail -f ~/.openclaw/logs/security-events.log
```

### Disable hooks temporarily

Rename the hook files:
```bash
cd ~/.claude-code/hooks/
mv user-prompt-submit-hook.ts user-prompt-submit-hook.ts.disabled
```

Or disable in config:
```yaml
openclaw_security:
  enabled: false
```

## Advanced Configuration

### Sensitivity Levels

- **paranoid** - Maximum security, may have false positives
- **strict** - High security with balanced accuracy
- **medium** - Default, good balance (recommended)
- **permissive** - Minimal blocking, focus on logging

### Module-Specific Settings

Override sensitivity per module:

```yaml
modules:
  prompt_injection:
    enabled: true
    sensitivity: strict
  command_validator:
    enabled: true
    sensitivity: paranoid
  url_validator:
    enabled: true
    sensitivity: medium
```

### Custom Actions

Override actions by severity:

```yaml
actions:
  SAFE: allow
  LOW: allow        # Don't even log low severity
  MEDIUM: log       # Log but allow
  HIGH: warn        # Show warning but allow
  CRITICAL: block   # Block without notification
```

## Integration Examples

### GitHub Actions

```yaml
- name: Install OpenClaw Security
  run: |
    npm install -g openclaw-sec
    cd ~/.claude-code/hooks/
    openclaw-sec install-hooks
```

### Docker

```dockerfile
FROM node:18
RUN npm install -g openclaw-sec
RUN mkdir -p /root/.claude-code/hooks
RUN openclaw-sec install-hooks
```

### CI/CD Pipeline

```bash
# Pre-commit validation
git diff --staged | openclaw-sec scan-content --stdin
```

## Support

- **Documentation:** See main [README.md](../README.md)
- **Issues:** Report at GitHub
- **Configuration:** See [SKILL.md](../SKILL.md)

## License

Part of the OpenClaw Security Suite - See LICENSE file
