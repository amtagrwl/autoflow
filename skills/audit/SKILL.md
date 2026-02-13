---
name: audit
description: >
  Analyze Claude Code permission patterns and recommend auto-allow rules to improve flow state.
  Shows flow score, interruption metrics, multi-level analysis, and before/after projections.
  Invoke at the start of a session or between tasks. Never invoke mid-task.
allowed-tools: Read, Edit, Bash(python3 *)
disable-model-invocation: false
user-invocable: true
---

# Autoflow Audit

You are running the autoflow audit skill. Follow these steps precisely:

## Step 1: Run Full Analysis

Run the analysis engine:

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/analyze.py --mode full --days 7
```

Parse the JSON output. If the output is empty or `{}`, tell the user there's not enough data yet and suggest they try again after a few sessions.

## Step 2: Present the Flow Score Dashboard

Format the output as a clear report. Start with:

```
## Autoflow Report (Last 7 Days)

Sessions: {sessions} | Tool calls: {total} | Permission prompts: {prompted}

### Flow Score: {current}% → projected {projected}%

Current:   {bar} {current}%  (avg {avg_streak} uninterrupted calls)
Projected: {bar} {projected}%  (avg {proj_streak} uninterrupted calls)
```

For the progress bars, use filled/empty block characters scaled to 10 chars.

## Step 3: Show Multi-Level Analysis

Group patterns by their top-level command. For each group show a tree:

```
  {command} ({total} total calls)
  ├─ Bash({command} *)           {status at broad level}
  ├─ Bash({sub} *)    {count}x approved, {denied} denied  {risk icon}  {flow%}
  ...
```

Use these icons:
- `✓ low risk` — 0 denials, 5+ approvals, not destructive
- `⚠ medium` — 0 denials but destructive or < 5 approvals
- `✗ high risk` — any denials

## Step 4: Show Top Recommendations Table

Show the top recommendations (up to 10) sorted by flow impact:

```
### Top Recommendations

 #  Pattern              Approved  Denied  Risk  Flow Impact
 1  Bash(python3 *)           86       0   low      +5.4%
 ...
```

Only include `low` risk recommendations in the table. Mention medium/high risk patterns separately if notable.

## Step 5: Interactive Apply

Walk through recommendations ONE AT A TIME, starting with highest flow impact:

```
Apply #1 Bash(python3 *)? (approved 86x, denied 0x, +5.4% flow) [y/n/skip]
```

Wait for the user to respond.

- On **yes** (`y`): Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/analyze.py --mode apply --pattern "THE_PATTERN"`. Show the result and updated flow score.
- On **no** or **skip**: Skip and move to the next recommendation.
- On **done** or **quit**: Stop the apply loop and show summary.

After each apply, show:
```
✓ Added {pattern} to settings.json
  Flow score: {old}% → {new}%
```

## Step 6: Summary

After all recommendations are processed (or user says done), show:

```
Done! {count} rules applied. Restart session for changes to take effect.
Final flow score: {final}% (was {original}%)
```

## Important Notes

- Never invoke this skill mid-task. Only at session start or between tasks.
- If there are no recommendations, say "Your flow is already optimized!" and show the current score.
- Be concise. Don't over-explain each recommendation — the data speaks for itself.
- If the user asks about a specific pattern, explain the multi-level analysis for that command group.
