---
name: audit
description: >
  Analyze Claude Code permission patterns and recommend auto-allow rules to improve flow state.
  Uses multi-level drill-down to reason about safety per command family.
  Invoke at the start of a session or between tasks. Never invoke mid-task.
allowed-tools: [Read, Edit, AskUserQuestion, "Bash(python3 *)"]
disable-model-invocation: false
---

# Autoflow Audit

## Step 1: Run Analysis & Parse Programmatically

Run the analysis and extract the fields you need via a python one-liner. **NEVER print or display the raw JSON** — it is too large. Always pipe through a parser.

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/analyze.py --mode full --days 7 2>&1 | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'sessions={d[\"sessions\"]} calls={d[\"total_calls\"]} prompted={d[\"prompted\"]} denied={d[\"denied\"]}')
print(f'interval={d[\"prompt_interval_display\"]} projected={d[\"projected_interval_display\"]}')
print(f'allow_list_size={len(d.get(\"current_allow_list\",[]))}')
print('--- RECOMMENDATIONS ---')
for r in d.get('recommendations',[]):
    print(f'L{r[\"level\"]} {r[\"pattern\"]:50s} approved={r[\"approved\"]:3d} denied={r[\"denied\"]:2d} chained={r.get(\"chained_count\",0):3d} cat={r[\"category\"]}')
"
```

This gives you the compact recommendation list. To examine a specific command family's examples and raw commands, use drill-down (Step 2).

If the output is empty or `{}`, tell the user there's not enough data yet.

## Step 2: Curate Recommendations

The script returns recommendations at ALL levels of specificity. **Your job is to pick the most specific safe level** — never recommend a broad pattern when more specific sub-patterns exist and are sufficient.

### Decision process for EACH command family:

1. **Start from the deepest level available** and work UP, not down.
   - If `Bash(uv run ruff *)` and `Bash(uv run pytest *)` cover the user's actual usage, recommend THOSE — not `Bash(uv run *)`.
   - Only go broader if dozens of distinct subcommands all look safe.

2. **Look for verb patterns (level=-1).** These use mid-wildcards and are often the best recommendation.
   - `Bash(gcloud * list *)` matches ALL gcloud list operations — read-only regardless of service
   - `Bash(gcloud * describe *)` matches ALL gcloud describe operations — read-only
   - `Bash(gh * view *)` matches ALL gh view operations — read-only
   - Verb patterns are **much better than prefix patterns** for CLI tools with deep subcommand hierarchies because one pattern covers all safe operations across all services.
   - Prefer verb patterns when the verb is inherently safe (list, describe, view, show, status, log, read, check, diff).
   - Avoid verb patterns for verbs that can be destructive (create, update, delete, deploy, execute).

3. **Check the `chained_count` field.** This is critical.
   - `chained_count > 0` means some commands matching this pattern contain `&&`, `||`, or `;`.
   - `Bash(git add *)` with chained_count=53 means 53 commands were `git add ... && git commit ... && git push ...` — allowing this pattern would auto-allow the entire chain including push.
   - **NEVER recommend a pattern with high chained_count** without drilling into the examples to understand what's chained.
   - If a command is commonly chained with destructive ops, **do NOT recommend it** — note why in your output.

4. **Use your knowledge of the CLI to assess safety:**
   - `Bash(cat *)` — read-only regardless of arguments → broad is fine
   - `Bash(gcloud *)` — would allow `gcloud iam set-policy`, `gcloud secrets` → NEVER, use verb patterns or specific subcommands
   - `Bash(uv run *)` — would allow `uv run rm -rf /` → NEVER, recommend specific tools (`uv run ruff *`, `uv run pytest *`)
   - `Bash(gh api *)` — would allow `gh api -X DELETE ...` → too broad, skip
   - `Bash(git add *)` — commonly chained with `git commit && git push` → DON'T recommend

5. **Drill down when unsure.** Call the script again with filters — run as many as you need, in parallel when independent. The `--include` flag supports the same glob syntax as the patterns:
   - `--include "gcloud"` — zoom into one command family
   - `--include "gcloud * list"` — see all gcloud list commands (verb-based drill-down)
   - `--include "gcloud * describe"` — see all gcloud describe commands
   - `--include "gh * view"` — see all gh view commands
   - `-e "delete|rm|drop"` — find destructive-looking commands
   - `-e "secret|password|token"` — find commands touching sensitive data
   - `-e "&&"` — find all chained commands
   - Combine: `--include "kubectl" -e "apply|create"`

### Good vs Bad examples:

**BAD** (too broad — allows destructive subcommands):
```
1. `Bash(uv run *)` — can run ANY script
2. `Bash(gh api *)` — can POST/DELETE
3. `Bash(git add *)` — 53/59 calls chained with commit+push!
4. `Bash(gcloud *)` — allows iam set-policy, secrets
5. `Bash(gcloud run jobs *)` — still allows `gcloud run jobs delete`
```

**GOOD** (scoped to safe operations — uses verb patterns and deep prefixes):
```
1. `Bash(gcloud * list *)` — ALL gcloud list ops, read-only (verb pattern)
2. `Bash(gcloud * describe *)` — ALL gcloud describe ops, read-only (verb pattern)
3. `Bash(uv run ruff *)` — lint & format only
4. `Bash(uv run pytest *)` — test runner only
5. `Bash(gcloud logging read *)` — read logs, pure read-only
6. `Bash(cat *)` — inherently read-only, broad is fine
```

The principle: **use verb patterns** (`Bash(tool * safe-verb *)`) when the verb is inherently safe (list, describe, view, read, check, diff, show, status). Use **deep prefix patterns** when scoping to a specific safe tool (`uv run ruff *`, `uv run pytest *`). Use **broad prefixes** only for inherently read-only tools (`cat *`, `which *`).

**Present 6-10 curated recommendations.** You are the safety layer.

### Category Reference (for your judgment, not shown to user)

| Category | What it means |
|---|---|
| `readonly` | No side effects — searches, reads, lookups |
| `run_code` | Runs code locally — tests, builds, scripts |
| `git_safe` | Read-only git — log, diff, status |
| `git_local_mutate` | Local git changes — add, commit, checkout |
| `git_remote_mutate` | Pushes/pulls — affects remote |
| `external_mutate` | Creates PRs, issues, or modifies external services |
| `file_write` | Edits files on disk |
| `claude_internal` | Claude's own tools (TaskUpdate, etc.) |
| `browser_action` | Clicks on live web pages |
| `infra` | Cloud/infra commands (gcloud, terraform, etc.) |

## Step 2.5: Learn from past audits

Read `${CLAUDE_PLUGIN_ROOT}/knowledge/audit-learnings.md` if it exists. Use it to inform your recommendations — e.g., if it says the user prefers scoped patterns, don't propose broad ones.

After the audit completes (Step 4), **update** the learnings file. This is a living document — edit/replace stale content, don't just append. Keep it concise (under 30 lines). Structure:

```markdown
# Audit Learnings

## User style
- [risk tolerance, comfort areas, caution areas — update as you learn more]

## Patterns accepted
- [pattern]: [why it's safe] — since YYYY-MM-DD

## Patterns rejected
- [pattern]: [user's reason] — propose again when [condition]

## Next audit suggestions
- [things to try next time]
```

## Step 3: Present Output

Be concise. The entire output should be scannable in 10 seconds.

**Format:**

```
Claude currently needs your permission every {prompt_interval_display}.
With these changes: every {projected_interval_display}.

{sessions} sessions, {total_calls} tool calls analyzed.

Recommendations:
1. `Bash(gcloud * list *)` — all gcloud list operations, 33x approved
2. `Bash(gcloud * describe *)` — all gcloud describe operations, 17x approved
3. `Bash(uv run pytest *)` — test runner, 34x approved
4. `Bash(gcloud logging read *)` — read Cloud Run logs, 34x approved
...

Skipped (too broad or chained):
- `Bash(git add *)` — 90% chained with commit+push
- `Bash(gcloud run jobs *)` — would also match delete/update
```

Rules:
- Use `prompt_interval_display` and `projected_interval_display` for timing values.
- One line per recommendation. Pattern name, plain-English description, approval count.
- Write the description yourself from the category and pattern name.
- Sort by flow impact descending.
- Show your curated 6-10 recommendations, not the raw list.
- Briefly list patterns you intentionally skipped and why (2-3 bullets).
- If `current_allow_list` is empty, mention they haven't set up any auto-allows yet.

## Step 4: Apply via AskUserQuestion

After showing the curated list, use `AskUserQuestion` with `multiSelect: true` to let the user pick which recommendations to apply.

**How to pick the 4 options:**
- Choose the best 4 from your curated list to surface as selectable options.
- Use your judgment: consider safety (category), impact (approval count), and likelihood of acceptance.
- Each option `label` is the pattern name (e.g. "`Bash(uv run ruff *)`"), `description` briefly explains what it does and the approval count.

**After user selects:**
- Apply each selected pattern by running `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/analyze.py --mode apply --pattern "PATTERN"` for each.
- If the user selects "Other", they can specify numbers from the full list — apply those.
- Show a single summary at the end: `Done! {count} rules applied. Restart session for changes to take effect.`
- Update `${CLAUDE_PLUGIN_ROOT}/knowledge/audit-learnings.md` per Step 2.5 (edit in place, don't just append).
