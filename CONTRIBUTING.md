# Contributing

Thanks for your interest in contributing to Shieldon Skills.

## Scope

Skills in this repo must address threat vectors in the AI agent ecosystem:

- Agent skills vectors, including but not limited to credential theft, prompt injection, supply chain attacks, data exfiltration, obfuscation and evasion techniques
- MCP communication
- A2A communication
- x402 payments
- ERC-8004 agentic reputation
- Other applicable vectors

## Acceptance Criteria

- Skill must include `SKILL.md` with proper frontmatter (`name`, `description` required)
- `name` field must match the parent directory name (lowercase letters, numbers, hyphens)

## Process

1. Fork this repo
2. Create your skill in `skills/<name>/`
3. Follow the [Agent Skills specification](https://agentskills.io/specification)
4. Open a pull request with a description of what your skill detects and why

## Adding Detection Patterns to skills-audit

To add new regex patterns to the existing `skills-audit` scanner:

1. Add the pattern to the `RULES` list in `skills/skills-audit/scripts/scan.py`
2. Include `name`, `description`, `severity`, and `patterns` fields
3. Add a test case showing the pattern triggers on malicious content
4. Verify existing benign files still pass as SAFE
5. Update `skills/skills-audit/references/DETECTION-COVERAGE.md`
