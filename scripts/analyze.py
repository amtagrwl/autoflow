#!/usr/bin/env python3
"""autoflow — Permission Flow Optimizer for Claude Code.

Analyzes Claude Code session transcripts to find permission patterns
and recommend auto-allow rules that improve flow state.

Python 3.6+, stdlib only.
"""

import argparse
import collections
import datetime
import fnmatch
import glob
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Destructive command patterns — these should stay prompted even if never denied
# ---------------------------------------------------------------------------
DESTRUCTIVE_PATTERNS = [
    "git push", "git push *",
    "git reset --hard", "git reset --hard *",
    "git rebase", "git rebase *",
    "git clean", "git clean *",
    "git branch -D", "git branch -D *",
    "git checkout .", "git restore .",
    "gh pr create", "gh pr create *",
    "gh pr merge", "gh pr merge *",
    "gh pr close", "gh pr close *",
    "gh issue create", "gh issue create *",
    "gh issue close", "gh issue close *",
    "rm", "rm *",
    "rm -rf", "rm -rf *",
    "rmdir", "rmdir *",
    "chmod", "chmod *",
    "chown", "chown *",
    "kill", "kill *",
    "killall", "killall *",
    "sudo", "sudo *",
    "docker rm", "docker rm *",
    "docker rmi", "docker rmi *",
    "kubectl delete", "kubectl delete *",
]

# Keywords that make any command destructive
DESTRUCTIVE_KEYWORDS = ["--force", "--hard", "delete", "drop", "destroy", "purge", "--no-verify"]


def is_destructive(command: str) -> bool:
    """Check if a command matches known destructive patterns."""
    cmd_lower = command.lower().strip()
    for pat in DESTRUCTIVE_PATTERNS:
        if fnmatch.fnmatch(cmd_lower, pat) or cmd_lower == pat:
            return True
    for kw in DESTRUCTIVE_KEYWORDS:
        if kw in cmd_lower:
            return True
    return False


def _parse_ts(ts_str):
    """Parse ISO 8601 timestamp to datetime."""
    if not ts_str:
        return None
    try:
        return datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        try:
            return datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None


def _median(values):
    """Compute median of a list of numbers."""
    if not values:
        return 0
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2


def _fmt_interval(seconds):
    """Format an interval in the most readable unit."""
    if seconds < 60:
        return f"{round(seconds, 1)} sec"
    if seconds < 3600:
        return f"{round(seconds / 60, 1)} min"
    return f"{round(seconds / 3600, 1)} hr"


# Built-in tools that are always auto-allowed (never prompted)
_BUILTIN_AUTO_TOOLS = {
    # Read-only — no approval required (per docs)
    "Read", "Glob", "Grep", "WebSearch",
    # Claude internal — never prompted
    "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
    "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "Skill",
}


# ---------------------------------------------------------------------------
# Tool classification
# ---------------------------------------------------------------------------
# MCP tool prefixes that indicate read-only operations
_READONLY_MCP_PREFIXES = ("read_", "get_", "list_", "view_", "tabs_context", "tabs_create")
# MCP tool keywords that indicate mutating operations
_MUTATE_MCP_KEYWORDS = ("write", "create", "delete", "merge", "close", "update", "edit", "remove")

def classify_tool(pattern: str) -> str:
    """Categorize a permission pattern for LLM judgment.

    Categories:
      readonly, run_code, git_safe, git_local_mutate, git_remote_mutate,
      external_mutate, claude_internal, file_write, browser_action, infra, unknown
    """
    # Non-Bash tools
    if not pattern.startswith("Bash("):
        name = pattern
        if name in ("Grep", "Glob", "Read", "WebSearch", "WebFetch"):
            return "readonly"
        if name in ("Write", "Edit", "NotebookEdit"):
            return "file_write"
        if name in ("TaskUpdate", "TaskCreate", "TaskList", "TaskGet",
                     "ExitPlanMode", "EnterPlanMode", "AskUserQuestion", "Skill"):
            return "claude_internal"
        # MCP tools
        if name.startswith("mcp__"):
            # Browser action tools
            if name.endswith("__computer") or name.endswith("__form_input"):
                return "browser_action"
            # Check for read-only MCP patterns
            suffix = name.split("__")[-1] if "__" in name else name
            for prefix in _READONLY_MCP_PREFIXES:
                if suffix.startswith(prefix):
                    return "readonly"
            # Check for mutating MCP patterns
            for kw in _MUTATE_MCP_KEYWORDS:
                if kw in suffix:
                    return "external_mutate"
            return "readonly"  # default MCP tools to readonly
        return "unknown"

    # Bash patterns — extract the inner command
    inner = pattern[5:-1]  # strip Bash( and )
    if inner.endswith(" *"):
        inner = inner[:-2]
    parts = inner.split()
    if not parts:
        return "unknown"
    cmd = parts[0]
    sub = parts[1] if len(parts) >= 2 else ""

    # Read-only shell commands
    if cmd in ("ls", "find", "wc", "which", "pwd", "cat", "head", "tail",
               "file", "stat", "du", "df", "echo", "date", "uname", "env",
               "printenv", "id", "whoami", "hostname"):
        return "readonly"

    # Git commands
    if cmd == "git":
        if sub in ("log", "status", "diff", "show", "branch", "tag", "remote",
                    "describe", "rev-parse", "ls-files", "ls-tree", "shortlog",
                    "blame", "reflog", "stash list"):
            return "git_safe"
        if sub in ("add", "commit", "checkout", "stash", "switch", "merge",
                    "cherry-pick", "revert", "tag -a", "branch -d"):
            return "git_local_mutate"
        if sub in ("push", "rebase", "reset", "fetch", "pull", "clean"):
            return "git_remote_mutate"
        return "git_safe"  # default unknown git subcommands to safe

    # Code execution
    if cmd in ("python3", "python", "node", "npm", "npx", "yarn", "pnpm",
               "uv", "cargo", "pytest", "jest", "vitest", "make", "go",
               "rustc", "tsc", "bun", "deno"):
        return "run_code"

    # Infrastructure
    if cmd in ("gcloud", "terraform", "tofu", "aws", "kubectl", "helm",
               "docker", "docker-compose", "pulumi", "az", "flyctl"):
        return "infra"

    # GitHub CLI
    if cmd == "gh":
        return "external_mutate"

    return "unknown"


# ---------------------------------------------------------------------------
# Transcript parsing
# ---------------------------------------------------------------------------
def find_transcripts(days: int) -> list:
    """Find JSONL transcript files modified within the last N days."""
    claude_dir = Path.home() / ".claude" / "projects"
    if not claude_dir.exists():
        return []

    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    results = []

    for jsonl_path in claude_dir.rglob("*.jsonl"):
        try:
            mtime = datetime.datetime.fromtimestamp(jsonl_path.stat().st_mtime)
            if mtime >= cutoff:
                results.append(jsonl_path)
        except OSError:
            continue

    return sorted(results, key=lambda p: p.stat().st_mtime, reverse=True)


def parse_transcript(path: Path) -> list:
    """Parse a JSONL transcript, returning list of (tool_name, command, outcome, timestamp) tuples.

    outcome is 'approved', 'denied', or 'auto' (already auto-allowed).
    timestamp is the ISO 8601 string from the assistant message containing the tool_use.
    """
    tool_calls = {}  # tool_use_id -> (tool_name, command, timestamp)
    results = []

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Content can be at entry["content"] or entry["message"]["content"]
                message = entry.get("message", {})
                content = message.get("content") if message else None
                if content is None:
                    content = entry.get("content", [])

                # Look for tool_use in assistant messages
                if entry.get("type") == "assistant":
                    if isinstance(content, str):
                        continue
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_use":
                                tool_id = block.get("id", "")
                                tool_name = block.get("name", "")
                                inp = block.get("input", {})
                                command = inp.get("command", "") if isinstance(inp, dict) else ""
                                tool_calls[tool_id] = (tool_name, command, entry.get("timestamp", ""))

                # Look for tool_result in user messages
                if entry.get("type") == "user":
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_result":
                                tool_id = block.get("tool_use_id", "")
                                result_content = block.get("content", "")
                                if isinstance(result_content, list):
                                    result_content = " ".join(
                                        str(item.get("text", "") if isinstance(item, dict) else item)
                                        for item in result_content
                                    )
                                elif not isinstance(result_content, str):
                                    result_content = str(result_content)

                                if tool_id in tool_calls:
                                    tool_name, command, ts = tool_calls[tool_id]
                                    if "doesn't want to proceed" in result_content:
                                        outcome = "denied"
                                    else:
                                        outcome = "approved"
                                    results.append((tool_name, command, outcome, ts))
    except (OSError, IOError):
        pass

    return results


def compute_prompt_intervals(all_calls, allow_list):
    """Compute intervals (seconds) between permission prompts during active work.

    Groups calls into active windows (gaps < 5 min between any consecutive calls).
    Returns list of inter-prompt intervals within those windows.
    """
    AFK_THRESHOLD = 300  # 5 minutes

    # Parse timestamps and determine prompted status
    timed_calls = []
    for tool_name, command, outcome, ts_str in all_calls:
        ts = _parse_ts(ts_str)
        if ts is None:
            continue
        prompted = not any(is_pattern_allowed(p, allow_list) for _, p in extract_patterns(tool_name, command))
        timed_calls.append((ts, prompted))

    timed_calls.sort(key=lambda x: x[0])

    if not timed_calls:
        return []

    # Group into active windows
    windows = []
    current_window = [timed_calls[0]]
    for i in range(1, len(timed_calls)):
        gap = (timed_calls[i][0] - timed_calls[i - 1][0]).total_seconds()
        if gap > AFK_THRESHOLD:
            windows.append(current_window)
            current_window = [timed_calls[i]]
        else:
            current_window.append(timed_calls[i])
    windows.append(current_window)

    # Collect inter-prompt intervals within each window
    intervals = []
    for window in windows:
        prompted_times = [ts for ts, prompted in window if prompted]
        for i in range(1, len(prompted_times)):
            intervals.append((prompted_times[i] - prompted_times[i - 1]).total_seconds())

    return intervals


# ---------------------------------------------------------------------------
# Pattern extraction
# ---------------------------------------------------------------------------
def extract_patterns(tool_name: str, command: str) -> list:
    """Extract hierarchical permission patterns from a tool call.

    Returns list of (level, pattern) tuples:
      - Prefix patterns at every subcommand depth (level 0, 1, 2, ...)
      - Verb patterns using mid-wildcards (level -1), e.g. Bash(gcloud * list *)
        These match the verb (last subcommand) regardless of intermediate path.
    """
    if tool_name != "Bash":
        return [(0, tool_name)]

    if not command.strip():
        return [(0, "Bash")]

    parts = command.strip().split()
    base = parts[0]
    patterns = [(0, f"Bash({base} *)")]

    prefix_parts = [base]
    for i, token in enumerate(parts[1:], start=1):
        if (token.startswith("-") or token.startswith("/") or token.startswith(".")
                or token in ("&&", "||", ";", "|")):
            break
        prefix_parts.append(token)
        patterns.append((i, f"Bash({' '.join(prefix_parts)} *)"))

    # Verb pattern: Bash(base * verb *) — matches the verb regardless of
    # intermediate subcommands. Only emitted when there are 3+ subcommand
    # tokens and the verb looks like a real CLI verb (not a redirect, number,
    # or resource name).
    _CLI_VERBS = {
        # read-only
        "list", "describe", "view", "read", "check", "diff", "show", "status",
        "log", "format", "inspect", "info", "get", "search", "find", "cat",
        "ls", "tree", "history", "blame", "watch", "tail", "top",
        # mutating (still useful to track, LLM decides safety)
        "create", "delete", "update", "deploy", "execute", "apply", "remove",
        "destroy", "set", "add", "push", "pull", "run", "start", "stop",
        "restart", "build", "submit", "merge", "close", "edit", "write",
        "install", "uninstall", "upgrade", "rollback", "scale", "attach",
    }
    if len(prefix_parts) >= 3:
        verb = prefix_parts[-1].lower()
        if verb in _CLI_VERBS:
            verb_pat = f"Bash({base} * {prefix_parts[-1]} *)"
            if verb_pat not in {p for _, p in patterns}:
                patterns.append((-1, verb_pat))

    return patterns


def pattern_to_settings_format(pattern: str) -> str:
    """Convert display pattern to settings.json format.

    Bash(git status *) -> Bash(git status *)
    Already in the right format for Claude Code settings.
    """
    return pattern


# ---------------------------------------------------------------------------
# Settings.json interaction
# ---------------------------------------------------------------------------
def load_settings() -> dict:
    """Load ~/.claude/settings.json."""
    settings_path = Path.home() / ".claude" / "settings.json"
    if not settings_path.exists():
        return {}
    try:
        with open(settings_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def get_allow_list(settings: dict) -> list:
    """Get the permissions.allow list from settings."""
    return settings.get("permissions", {}).get("allow", [])


def is_pattern_allowed(pattern: str, allow_list: list) -> bool:
    """Check if a pattern is already covered by the allow list."""
    settings_pat = pattern_to_settings_format(pattern)
    for allowed in allow_list:
        if allowed == settings_pat:
            return True
        # Check if a broader pattern covers this one
        # e.g., Bash(git *) covers Bash(git status *)
        if fnmatch.fnmatch(settings_pat, allowed):
            return True
    return False


def apply_pattern(pattern: str) -> dict:
    """Add a pattern to settings.json permissions.allow."""
    settings_path = Path.home() / ".claude" / "settings.json"

    settings = load_settings()
    if "permissions" not in settings:
        settings["permissions"] = {}
    if "allow" not in settings["permissions"]:
        settings["permissions"]["allow"] = []

    settings_pat = pattern_to_settings_format(pattern)

    if settings_pat not in settings["permissions"]["allow"]:
        settings["permissions"]["allow"].append(settings_pat)

    try:
        with open(settings_path, "w") as f:
            json.dump(settings, f, indent=2)
            f.write("\n")
        return {"success": True, "pattern": settings_pat, "settings_path": str(settings_path)}
    except OSError as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------
def analyze(days: int, include=None, expr=None, max_depth=None) -> dict:
    """Run full analysis and return structured results.

    Filtering (any combination):
      include  — keep only Bash patterns/groups whose command starts with this prefix
      expr     — keep only patterns/groups where any raw command matches (substring or regex)
      max_depth — exclude patterns with level > this value from recommendations
    When any filter is active, a "raw_commands" field is added with up to 20 matching commands.
    """
    transcripts = find_transcripts(days)
    if not transcripts:
        return {}

    settings = load_settings()
    allow_list = get_allow_list(settings)
    effective_allow = allow_list + list(_BUILTIN_AUTO_TOOLS)

    # Collect all tool calls
    all_calls = []
    for t in transcripts:
        calls = parse_transcript(t)
        all_calls.extend(calls)

    if not all_calls:
        return {}

    filtered = bool(include or expr)

    # Count by pattern
    pattern_counts = {}  # pattern -> {"approved": N, "denied": N, "level": N}

    for tool_name, command, outcome, _ts in all_calls:
        patterns = extract_patterns(tool_name, command)
        for level, pattern in patterns:
            if pattern not in pattern_counts:
                pattern_counts[pattern] = {"approved": 0, "denied": 0, "level": level}
            if outcome == "approved":
                pattern_counts[pattern]["approved"] += 1
            elif outcome == "denied":
                pattern_counts[pattern]["denied"] += 1

    # Track raw command examples per pattern (up to 5 each)
    pattern_examples = collections.defaultdict(list)
    for tool_name, command, outcome, _ts in all_calls:
        patterns = extract_patterns(tool_name, command)
        for level, pattern in patterns:
            if len(pattern_examples[pattern]) < 5:
                pattern_examples[pattern].append(command)

    # Track chained commands (&&, ||, ;) per pattern — these are dangerous
    # because Bash(git add *) would also auto-allow "git add . && git push"
    _CHAIN_OPS = re.compile(r'\s*(?:&&|\|\||;)\s*')
    pattern_chain_counts = collections.defaultdict(int)
    for tool_name, command, outcome, _ts in all_calls:
        if tool_name == "Bash" and _CHAIN_OPS.search(command):
            patterns = extract_patterns(tool_name, command)
            for level, pattern in patterns:
                pattern_chain_counts[pattern] += 1

    # Mark destructive and already-allowed
    for pattern, stats in pattern_counts.items():
        inner = pattern
        if inner.startswith("Bash(") and inner.endswith(")"):
            inner_cmd = inner[5:-1]
            if inner_cmd.endswith(" *"):
                inner_cmd = inner_cmd[:-2]
            stats["destructive"] = is_destructive(inner_cmd)
        else:
            stats["destructive"] = False
        stats["already_allowed"] = is_pattern_allowed(pattern, effective_allow)

    # Classify risk
    for pattern, stats in pattern_counts.items():
        if stats["denied"] > 0:
            stats["risk"] = "high"
        elif stats["destructive"] or stats["approved"] < 5:
            stats["risk"] = "medium"
        else:
            stats["risk"] = "low"

    # --- Filter helpers ---
    # Normalize include to a glob: "gcloud" -> "gcloud*", "gcloud * list" -> "gcloud * list*"
    _include_glob = None
    if include:
        _include_glob = include if "*" in include else include + "*"
        if not _include_glob.endswith("*"):
            _include_glob += "*"

    def _pattern_matches_include(pattern):
        """Check if pattern's command matches the include glob."""
        if not _include_glob:
            return True
        if not pattern.startswith("Bash("):
            return False
        inner = pattern[5:-1]
        if inner.endswith(" *"):
            inner = inner[:-2]
        return fnmatch.fnmatch(inner, _include_glob)

    def _command_matches_include(command):
        """Check if a raw command matches the include glob."""
        if not _include_glob:
            return True
        return fnmatch.fnmatch(command, _include_glob)

    def _command_matches_expr(command):
        """Check if a raw command matches the expr (substring or regex)."""
        if not expr:
            return True
        try:
            return bool(re.search(expr, command))
        except re.error:
            return expr in command

    def _pattern_matches_expr(pattern):
        """Check if any example for this pattern matches expr."""
        if not expr:
            return True
        for cmd in pattern_examples.get(pattern, []):
            if _command_matches_expr(cmd):
                return True
        return False

    def _pattern_matches_filters(pattern):
        return _pattern_matches_include(pattern) and _pattern_matches_expr(pattern)

    # Group by top-level command for multi-level analysis
    groups = collections.defaultdict(list)
    for pattern, stats in pattern_counts.items():
        if not _pattern_matches_filters(pattern):
            continue
        if pattern.startswith("Bash("):
            inner = pattern[5:-1]
            top_cmd = inner.split()[0] if inner else pattern
            parts = inner.split()
            if len(parts) >= 2 and parts[0] in ("gh", "docker", "kubectl", "npm", "cargo"):
                top_cmd = f"{parts[0]} {parts[1]}" if stats["level"] == 1 else parts[0]
                if stats["level"] == 0:
                    top_cmd = parts[0]
            groups[top_cmd].append({
                "pattern": pattern,
                **stats,
                "examples": pattern_examples.get(pattern, []),
                "chained_count": pattern_chain_counts.get(pattern, 0),
            })
        else:
            groups[pattern].append({
                "pattern": pattern,
                **stats,
                "examples": pattern_examples.get(pattern, []),
                "chained_count": pattern_chain_counts.get(pattern, 0),
            })

    # Calculate counts
    total_calls = len(all_calls)

    auto_count = 0
    prompted_count = 0
    denied_count = 0

    for tool_name, command, outcome, _ts in all_calls:
        patterns = extract_patterns(tool_name, command)
        any_allowed = any(is_pattern_allowed(p, effective_allow) for _, p in patterns)
        if any_allowed:
            auto_count += 1
        elif outcome == "denied":
            denied_count += 1
            prompted_count += 1
        else:
            prompted_count += 1

    # Build recommendations
    recommendations = []
    for pattern, stats in pattern_counts.items():
        if stats["already_allowed"]:
            continue
        if stats["risk"] != "low":
            continue
        if not _pattern_matches_filters(pattern):
            continue
        if max_depth is not None and stats["level"] > max_depth:
            continue

        flow_impact = stats["approved"] / total_calls * 100 if total_calls > 0 else 0
        chained = pattern_chain_counts.get(pattern, 0)
        recommendations.append({
            "pattern": pattern,
            "approved": stats["approved"],
            "denied": stats["denied"],
            "risk": stats["risk"],
            "flow_impact": round(flow_impact, 1),
            "level": stats["level"],
            "category": classify_tool(pattern),
            "chained_count": chained,
        })

    # All levels go to the LLM — it decides the right granularity
    final_recommendations = list(recommendations)

    final_recommendations.sort(key=lambda r: r["flow_impact"], reverse=True)

    # Compute timing metrics
    current_intervals = compute_prompt_intervals(all_calls, effective_allow)
    prompt_interval = _median(current_intervals)

    projected_allow = effective_allow + [r["pattern"] for r in final_recommendations]
    projected_intervals = compute_prompt_intervals(all_calls, projected_allow)
    projected_interval = _median(projected_intervals)

    result = {
        "sessions": len(transcripts),
        "total_calls": total_calls,
        "auto_allowed": auto_count,
        "prompted": prompted_count,
        "denied": denied_count,
        "prompt_interval_minutes": round(prompt_interval / 60, 1),
        "projected_interval_minutes": round(projected_interval / 60, 1),
        "prompt_interval_seconds": round(prompt_interval, 1),
        "projected_interval_seconds": round(projected_interval, 1),
        "prompt_interval_display": _fmt_interval(prompt_interval),
        "projected_interval_display": _fmt_interval(projected_interval),
        "groups": {k: v for k, v in sorted(groups.items(), key=lambda x: sum(s["approved"] + s["denied"] for s in x[1]), reverse=True)},
        "recommendations": final_recommendations[:25],
        "current_allow_list": allow_list,
    }

    # When filters are active, include matching raw commands with outcomes
    if filtered:
        raw_commands = []
        for tool_name, command, outcome, _ts in all_calls:
            if tool_name != "Bash":
                continue
            if include and not _command_matches_include(command.strip()):
                continue
            if expr and not _command_matches_expr(command):
                continue
            raw_commands.append({"command": command, "outcome": outcome})
            if len(raw_commands) >= 20:
                break
        result["raw_commands"] = raw_commands

    return result


_QUICK_SKIP_CATEGORIES = {"claude_internal", "file_write", "browser_action", "external_mutate", "git_remote_mutate"}

def quick_recommendation(days: int) -> dict:
    """Return single top recommendation for session start hook."""
    result = analyze(days)
    if not result or not result.get("recommendations"):
        return {}

    top = None
    for rec in result["recommendations"]:
        if rec.get("category") not in _QUICK_SKIP_CATEGORIES:
            top = rec
            break
    if top is None:
        return {}
    interval_display = result.get("prompt_interval_display", "?")
    return {
        "recommendation": top["pattern"],
        "approved": top["approved"],
        "denied": top["denied"],
        "risk": top["risk"],
        "flow_impact": top["flow_impact"],
        "prompt_interval_display": interval_display,
        "message": (
            f"Autoflow tip: You're prompted every {interval_display}. "
            f"Allowing `{top['pattern']}` ({top['approved']}x approved, 0 denied) "
            f"would help. Run /autoflow:audit for full analysis."
        ),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="autoflow — Permission Flow Optimizer")
    parser.add_argument("--mode", choices=["full", "quick", "apply"], required=True,
                        help="Analysis mode")
    parser.add_argument("--days", type=int, default=7,
                        help="Number of days to analyze (default: 7)")
    parser.add_argument("--pattern", type=str,
                        help="Pattern to apply (for --mode apply)")
    parser.add_argument("--include", type=str,
                        help="Filter to commands starting with this prefix")
    parser.add_argument("-e", "--expr", type=str,
                        help="Filter to commands matching this expression")
    parser.add_argument("-n", "--max-depth", type=int,
                        help="Max pattern depth to include")
    args = parser.parse_args()

    if args.mode == "full":
        result = analyze(args.days, include=args.include, expr=args.expr,
                         max_depth=args.max_depth)
        print(json.dumps(result, indent=2))

    elif args.mode == "quick":
        result = quick_recommendation(args.days)
        print(json.dumps(result, indent=2))

    elif args.mode == "apply":
        if not args.pattern:
            print(json.dumps({"error": "--pattern is required for apply mode"}))
            sys.exit(1)
        result = apply_pattern(args.pattern)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
