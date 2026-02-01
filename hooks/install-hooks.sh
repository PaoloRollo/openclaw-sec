#!/bin/bash

# OpenClaw Security Suite - Hook Installation Script
#
# This script installs security hooks into Claude Code's hooks directory.
# Hooks will automatically validate user input and tool calls for security threats.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       OpenClaw Security Suite - Hook Installer          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Determine Claude Code hooks directory
HOOKS_DIR="${HOME}/.claude-code/hooks"

# Check if custom hooks directory is set
if [ -n "$CLAUDE_HOOKS_DIR" ]; then
    HOOKS_DIR="$CLAUDE_HOOKS_DIR"
fi

echo -e "${BLUE}→${NC} Hooks directory: ${HOOKS_DIR}"

# Create hooks directory if it doesn't exist
if [ ! -d "$HOOKS_DIR" ]; then
    echo -e "${YELLOW}→${NC} Creating hooks directory..."
    mkdir -p "$HOOKS_DIR"
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Install user-prompt-submit hook
echo -e "${BLUE}→${NC} Installing user-prompt-submit hook..."
if [ -f "$SCRIPT_DIR/user-prompt-submit-hook.ts" ]; then
    cp "$SCRIPT_DIR/user-prompt-submit-hook.ts" "$HOOKS_DIR/"
    chmod +x "$HOOKS_DIR/user-prompt-submit-hook.ts"
    echo -e "${GREEN}✓${NC} user-prompt-submit-hook.ts installed"
else
    echo -e "${RED}✗${NC} user-prompt-submit-hook.ts not found"
    exit 1
fi

# Install tool-call hook
echo -e "${BLUE}→${NC} Installing tool-call hook..."
if [ -f "$SCRIPT_DIR/tool-call-hook.ts" ]; then
    cp "$SCRIPT_DIR/tool-call-hook.ts" "$HOOKS_DIR/"
    chmod +x "$HOOKS_DIR/tool-call-hook.ts"
    echo -e "${GREEN}✓${NC} tool-call-hook.ts installed"
else
    echo -e "${RED}✗${NC} tool-call-hook.ts not found"
    exit 1
fi

# Create symlinks to source files (for development)
# This allows hooks to access the main codebase
if [ -d "$SCRIPT_DIR/../src" ]; then
    echo -e "${BLUE}→${NC} Creating symlink to source directory..."
    ln -sf "$SCRIPT_DIR/.." "$HOOKS_DIR/openclaw-sec"
    echo -e "${GREEN}✓${NC} Symlink created: $HOOKS_DIR/openclaw-sec"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Installation Complete! ✓                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Create a .openclaw-security.yaml config file"
echo -e "  2. Restart Claude Code to activate hooks"
echo -e "  3. Test with: echo '{\"userPrompt\":\"test\"}' | node $HOOKS_DIR/user-prompt-submit-hook.ts"
echo ""
echo -e "${YELLOW}Note:${NC} Hooks require the OpenClaw Security Suite to be installed."
echo -e "Run ${BLUE}npm install${NC} in $SCRIPT_DIR/.. if you haven't already."
echo ""
