# Instructions for Agents

This repo contains security skills for AI agents. If you're an agent working in this repo, read this first.

## Repo Structure

```
skills/
  skills-audit/           Security scanner for skill files
    SKILL.md              Instructions and usage
    scripts/scan.py       Python regex scanner (stdlib only)
    references/           Detection coverage docs
    assets/               Example output
```

Skills live in `skills/<skill-name>/`. Each skill has a `SKILL.md` with frontmatter and instructions following the [Agent Skills specification](https://agentskills.io/specification).

## Using the skills-audit skill

Scan a skill file before installing it:

```bash
python skills/skills-audit/scripts/scan.py --file /path/to/SKILL.md
python skills/skills-audit/scripts/scan.py --url https://example.com/SKILL.md
python skills/skills-audit/scripts/scan.py --content "skill text"
```

Output is JSON with `risk_score` (0-100), `risk_level`, `recommendation` (SAFE/REVIEW/BLOCK), and `findings[]`.

## Adding Detection Patterns

1. Edit `skills/skills-audit/scripts/scan.py` — add the new pattern to the `RULES` list
2. Add a test case (a `.md` file containing the malicious pattern) and verify the scanner detects it
3. Verify existing benign content still passes as SAFE
4. Update `skills/skills-audit/references/DETECTION-COVERAGE.md` with the new rule

## Adding a New Skill

1. Create `skills/<name>/SKILL.md` with proper frontmatter (`name`, `description` required)
2. The `name` field must match the directory name (lowercase, hyphens only)
3. Include usage instructions and example output in SKILL.md
4. Add any scripts to `skills/<name>/scripts/`

## Scope

This repo contains skills for AI agent security and AI commerce security only. Do not add skills unrelated to scanning, auditing, or protecting against security threats in the agent/MCP/skill ecosystem.
