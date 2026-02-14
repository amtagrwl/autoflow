# Audit Learnings

## User style
- Conservative — prefers scoped patterns over broad wildcards
- Comfortable with: read-only tools, specific lint/test tools (ruff, mypy, pytest)
- Cautious with: mutation commands, broad runners (`uv run *`, `gh api *`), chained commands

## Patterns accepted
- `Bash(uv run ruff *)`: lint/format only — 2026-02-14
- `Bash(uv run mypy *)`: type checking — 2026-02-14

## Patterns rejected
- `Bash(uv run *)`: too broad, can run arbitrary scripts
- `Bash(gh api *)`: can POST/DELETE, not just GET
- `Bash(git add *)`: 90% chained with commit+push
- `Bash(gcloud run *)`: too broad, propose verb patterns instead

### 2026-02-14 audit (session 2)

**User style observations:**
- Risk tolerance: conservative — consistent with previous audit
- Comfort areas: read-only tools, scoped lint/test/log commands
- Caution areas: declined `Edit` (505x approved) and `Bash(cd *)` (334x) despite high volume — prefers keeping review on file mutations and navigation

**Decisions this session:**
- Accepted: `Bash(uv run pytest *)` (scoped test runner), `Bash(gcloud logging read *)` (read-only logs)
- Declined: `Edit`, `Bash(cd *)` — user wants to keep review control on these
- Not selected: `Write`, `mcp__github__issue_read`, `Bash(which *)`, `Bash(gcloud * list *)`

**Suggestions for next audit:**
- Propose `Bash(gcloud * list *)` and `Bash(gcloud * describe *)` — read-only verb patterns, 33x approved
- Propose `Bash(gcloud builds submit *)` — 22x approved, build-only (no delete/update)
- Propose `mcp__github__issue_read` and `mcp__github__list_issues` — read-only GitHub tools
- Watch `Edit` and `cd` — if user continues approving 100% of the time, re-propose next audit
- Consider proposing `Bash(curl -s *)` (read-only health checks) — 37x approved but includes non-GET; maybe propose with `-s` flag only
