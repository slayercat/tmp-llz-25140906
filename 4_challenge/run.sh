#!/bin/bash
#
# ReAct Agent — Static Vulnerability Analysis
# One-click runner for analyzing targets/challenge
#
# Requirements:
#   - Python 3.9+ with openai package (pip install -r requirements.txt)
#   - radare2 at /opt/radare2-6.1.6/bin/r2
#   - Ghidra at /opt/ghidra_12.1.2_PUBLIC
#   - DeepSeek API key: export DEEPSEEK_API_KEY="sk-..."
#
# Paths:
#   R2_PATH=/opt/radare2-6.1.6/bin/r2
#   GHIDRA_HOME=/opt/ghidra_12.1.2_PUBLIC
#   GHIDRA_PROJECT=/tmp/ghidra_react_project

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check API key
if [ -z "$DEEPSEEK_API_KEY" ]; then
    echo "ERROR: DEEPSEEK_API_KEY is not set"
    echo "Usage: export DEEPSEEK_API_KEY='sk-...' && ./run.sh"
    exit 1
fi

# Verify tools exist
if [ ! -x "/opt/radare2-6.1.6/bin/r2" ]; then
    echo "ERROR: r2 not found at /opt/radare2-6.1.6/bin/r2"
    exit 1
fi
if [ ! -f "/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless" ]; then
    echo "ERROR: Ghidra not found at /opt/ghidra_12.1.2_PUBLIC"
    exit 1
fi
if [ ! -f "targets/challenge" ]; then
    echo "ERROR: target binary not found at targets/challenge"
    exit 1
fi

# Ensure output directories exist
mkdir -p logs output

# Install dependencies if needed
pip install -q -r requirements.txt 2>/dev/null || true

echo "=============================================="
echo "  ReAct Agent — Static Vulnerability Analysis"
echo "=============================================="
echo "Target: targets/challenge"
echo "Model:  deepseek-chat"
echo "Date:   $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

python3 agent.py
