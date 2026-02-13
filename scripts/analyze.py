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
    """Parse a JSONL transcript, returning list of (tool_name, command, outcome) tuples.

    outcome is 'approved', 'denied', or 'auto' (already auto-allowed).
    """
    tool_calls = {}  # tool_use_id -> (tool_name, command)
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
                                tool_calls[tool_id] = (tool_name, command)

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
                                    tool_name, command = tool_calls[tool_id]
                                    if "doesn't want to proceed" in result_content:
                                        outcome = "denied"
                                    else:
                                        outcome = "approved"
                                    results.append((tool_name, command, outcome))
    except (OSError, IOError):
        pass

    return results


# ---------------------------------------------------------------------------
# Pattern extraction
# ---------------------------------------------------------------------------
def extract_patterns(tool_name: str, command: str) -> list:
    """Extract hierarchical permission patterns from a tool call.

    Returns list of (level, pattern) tuples.
    Level 0 = broadest, level 1 = subcommand, etc.
    """
    if tool_name != "Bash":
        return [(0, tool_name)]

    if not command.strip():
        return [(0, "Bash")]

    parts = command.strip().split()
    base = parts[0]

    patterns = [(0, f"Bash({base} *)")]

    if len(parts) >= 2:
        sub = parts[1]
        # Skip if subcommand looks like a flag or path
        if not sub.startswith("-") and not sub.startswith("/") and not sub.startswith("."):
            patterns.append((1, f"Bash({base} {sub} *)"))

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
def analyze(days: int) -> dict:
    """Run full analysis and return structured results."""
    transcripts = find_transcripts(days)
    if not transcripts:
        return {}

    settings = load_settings()
    allow_list = get_allow_list(settings)

    # Collect all tool calls
    all_calls = []
    for t in transcripts:
        calls = parse_transcript(t)
        all_calls.extend(calls)

    if not all_calls:
        return {}

    # Count by pattern
    PatternStats = collections.namedtuple("PatternStats", ["approved", "denied", "destructive"])
    pattern_counts = {}  # pattern -> {"approved": N, "denied": N}

    for tool_name, command, outcome in all_calls:
        patterns = extract_patterns(tool_name, command)
        for level, pattern in patterns:
            if pattern not in pattern_counts:
                pattern_counts[pattern] = {"approved": 0, "denied": 0, "level": level}
            if outcome == "approved":
                pattern_counts[pattern]["approved"] += 1
            elif outcome == "denied":
                pattern_counts[pattern]["denied"] += 1

    # Mark destructive and already-allowed
    for pattern, stats in pattern_counts.items():
        # Check destructiveness based on the command inside the pattern
        inner = pattern
        if inner.startswith("Bash(") and inner.endswith(")"):
            inner_cmd = inner[5:-1]  # strip Bash( and )
            if inner_cmd.endswith(" *"):
                inner_cmd = inner_cmd[:-2]
            stats["destructive"] = is_destructive(inner_cmd)
        else:
            stats["destructive"] = False
        stats["already_allowed"] = is_pattern_allowed(pattern, allow_list)

    # Classify risk
    for pattern, stats in pattern_counts.items():
        if stats["denied"] > 0:
            stats["risk"] = "high"
        elif stats["destructive"] or stats["approved"] < 5:
            stats["risk"] = "medium"
        else:
            stats["risk"] = "low"

    # Group by top-level command for multi-level analysis
    groups = collections.defaultdict(list)
    for pattern, stats in pattern_counts.items():
        if pattern.startswith("Bash("):
            inner = pattern[5:-1]
            top_cmd = inner.split()[0] if inner else pattern
            # For two-word commands like "gh pr", group them together
            parts = inner.split()
            if len(parts) >= 2 and parts[0] in ("gh", "docker", "kubectl", "npm", "cargo"):
                top_cmd = f"{parts[0]} {parts[1]}" if stats["level"] == 1 else parts[0]
                if stats["level"] == 0:
                    top_cmd = parts[0]
            groups[top_cmd].append({"pattern": pattern, **stats})
        else:
            groups[pattern].append({"pattern": pattern, **stats})

    # Calculate flow metrics
    total_calls = len(all_calls)
    bash_calls = [(t, c, o) for t, c, o in all_calls if t == "Bash"]
    non_bash_calls = [(t, c, o) for t, c, o in all_calls if t != "Bash"]

    auto_count = 0
    prompted_count = 0
    denied_count = 0

    for tool_name, command, outcome in all_calls:
        patterns = extract_patterns(tool_name, command)
        any_allowed = any(is_pattern_allowed(p, allow_list) for _, p in patterns)
        if any_allowed:
            auto_count += 1
        elif outcome == "denied":
            denied_count += 1
            prompted_count += 1
        else:
            prompted_count += 1

    flow_score = (auto_count / total_calls * 100) if total_calls > 0 else 0

    # Calculate average streak (consecutive auto-allowed calls)
    streaks = []
    current_streak = 0
    for tool_name, command, outcome in all_calls:
        patterns = extract_patterns(tool_name, command)
        any_allowed = any(is_pattern_allowed(p, allow_list) for _, p in patterns)
        if any_allowed or tool_name not in ("Bash",):
            # Non-Bash tools like Read, Write, Edit, Glob, Grep are typically auto-allowed
            current_streak += 1
        else:
            if current_streak > 0:
                streaks.append(current_streak)
            current_streak = 0
    if current_streak > 0:
        streaks.append(current_streak)
    avg_streak = sum(streaks) / len(streaks) if streaks else 0

    # Build recommendations
    recommendations = []
    for pattern, stats in pattern_counts.items():
        if stats["already_allowed"]:
            continue
        if stats["risk"] != "low":
            continue
        if stats["level"] == 0:
            # For broad patterns, only recommend if ALL subcommands are safe
            inner = pattern[5:-1] if pattern.startswith("Bash(") else pattern
            top_cmd = inner.split()[0] if inner else pattern
            # Check if any subcommand has denials or is destructive
            has_issues = False
            for other_pattern, other_stats in pattern_counts.items():
                if other_stats["level"] == 1 and other_pattern.startswith(f"Bash({top_cmd} "):
                    if other_stats["denied"] > 0 or other_stats["destructive"]:
                        has_issues = True
                        break
            if has_issues:
                continue

        flow_impact = stats["approved"] / total_calls * 100 if total_calls > 0 else 0
        recommendations.append({
            "pattern": pattern,
            "approved": stats["approved"],
            "denied": stats["denied"],
            "risk": stats["risk"],
            "flow_impact": round(flow_impact, 1),
            "level": stats["level"],
        })

    # Remove level-0 recommendations if level-1 recommendations exist for same command
    # (prefer specific over broad when broad has subcommand issues)
    level0_patterns = {r["pattern"] for r in recommendations if r["level"] == 0}
    level1_cmds = set()
    for r in recommendations:
        if r["level"] == 1 and r["pattern"].startswith("Bash("):
            inner = r["pattern"][5:-1]
            top_cmd = inner.split()[0]
            level1_cmds.add(top_cmd)

    # If we have level-1 recs for a command, remove level-0 rec only if level-0 has issues
    final_recommendations = []
    for r in recommendations:
        if r["level"] == 0 and r["pattern"].startswith("Bash("):
            inner = r["pattern"][5:-1]
            top_cmd = inner.split()[0]
            if top_cmd in level1_cmds:
                # Check if level-0 would be strictly better
                level1_total = sum(
                    rec["flow_impact"] for rec in recommendations
                    if rec["level"] == 1 and rec["pattern"].startswith(f"Bash({top_cmd} ")
                )
                if r["flow_impact"] > level1_total:
                    # Broad pattern is better, keep it and remove level-1s
                    final_recommendations.append(r)
                    continue
                else:
                    # Level-1 patterns collectively cover more, skip broad
                    continue
        final_recommendations.append(r)

    # If broad pattern was kept, remove its level-1 children
    kept_broad = {
        r["pattern"][5:-1].split()[0]
        for r in final_recommendations
        if r["level"] == 0 and r["pattern"].startswith("Bash(")
    }
    final_recommendations = [
        r for r in final_recommendations
        if not (
            r["level"] == 1
            and r["pattern"].startswith("Bash(")
            and r["pattern"][5:-1].split()[0] in kept_broad
        )
    ]

    final_recommendations.sort(key=lambda r: r["flow_impact"], reverse=True)

    # Projected flow score
    projected_auto = auto_count + sum(r["approved"] for r in final_recommendations)
    projected_flow = (projected_auto / total_calls * 100) if total_calls > 0 else 0

    # Projected average streak (rough estimate)
    proj_streak = avg_streak * (projected_flow / flow_score) if flow_score > 0 else avg_streak

    return {
        "sessions": len(transcripts),
        "total_calls": total_calls,
        "auto_allowed": auto_count,
        "prompted": prompted_count,
        "denied": denied_count,
        "flow_score": round(flow_score, 1),
        "projected_flow": round(projected_flow, 1),
        "avg_streak": round(avg_streak, 1),
        "projected_streak": round(proj_streak, 1),
        "groups": {k: v for k, v in sorted(groups.items(), key=lambda x: sum(s["approved"] + s["denied"] for s in x[1]), reverse=True)},
        "recommendations": final_recommendations[:10],
    }


def quick_recommendation(days: int) -> dict:
    """Return single top recommendation for session start hook."""
    result = analyze(days)
    if not result or not result.get("recommendations"):
        return {}

    top = result["recommendations"][0]
    return {
        "recommendation": top["pattern"],
        "approved": top["approved"],
        "denied": top["denied"],
        "risk": top["risk"],
        "flow_impact": top["flow_impact"],
        "flow_score": result["flow_score"],
        "message": (
            f"Autoflow tip: Consider allowing `{top['pattern']}` "
            f"({top['approved']}x approved, 0 denied, +{top['flow_impact']}% flow). "
            f"Run /autoflow:audit for full analysis."
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
    args = parser.parse_args()

    if args.mode == "full":
        result = analyze(args.days)
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
