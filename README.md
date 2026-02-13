# autoflow

Iteratively optimize your Claude Code flow state.

autoflow analyzes your Claude Code permission patterns and recommends auto-allow rules to reduce interruptions. It measures "flow score" — the percentage of tool calls that don't require a permission prompt — and helps you improve it.

## Installation

```bash
claude plugin install ~/git/autoflow
```

Or run with:

```bash
claude --plugin-dir ~/git/autoflow/
```

## Usage

### Session Start Hook

autoflow silently injects one top recommendation at session start. If there's nothing to suggest, it stays completely silent.

### On-Demand Audit

```
/autoflow:audit
```

This runs a full analysis of the last 7 days of sessions and walks you through recommendations interactively.

### Direct CLI

```bash
# Full JSON report
python3 scripts/analyze.py --mode full --days 7

# Single recommendation for hook
python3 scripts/analyze.py --mode quick --days 7

# Apply a rule to settings.json
python3 scripts/analyze.py --mode apply --pattern "Bash(git status *)"
```

## How It Works

autoflow reads your Claude Code session transcripts (`~/.claude/projects/*/*.jsonl`) and:

1. Parses every tool call and its result
2. Classifies each as approved or denied
3. Extracts multi-level command patterns (e.g., `Bash(git *)` vs `Bash(git status *)`)
4. Cross-references against your current `~/.claude/settings.json` allow list
5. Flags destructive commands that should stay prompted
6. Recommends the optimal granularity level for each command group

### Multi-Level Analysis

For each command group, autoflow analyzes at multiple granularity levels:

- **Level 0 (broad):** `Bash(git *)` — covers all git commands
- **Level 1 (subcommand):** `Bash(git status *)` — covers one subcommand

If all uses at level 0 are safe (no denials, no destructive subcommands), it recommends the broad pattern. Otherwise, it recommends individual safe subcommands.

### Risk Levels

- **low** — 0 denials, 5+ approvals, not destructive
- **medium** — 0 denials but destructive or < 5 approvals
- **high** — any denials

## Requirements

- Python 3.6+ (stdlib only, no dependencies)
- Claude Code with session transcripts

## License

MIT
