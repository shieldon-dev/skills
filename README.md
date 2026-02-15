# Shieldon Skills

Agent skills for AI commerce security. Scan skills before you install them.

## Available Skills

| Skill | Description |
|-------|-------------|
| [`skills-audit`](skills/skills-audit/) | Security scanner — audits skill files for credential theft, exfiltration, dangerous commands, and obfuscation. Returns a structured risk report with score (0-100) and SAFE/REVIEW/BLOCK recommendation. |

## Install

```bash
npx skills add shieldon-dev/skills
```

Installs to Cursor, Claude Code, Codex, and [35+ other agents](https://github.com/vercel-labs/skills#supported-agents). Once installed, ask your agent to scan a skill before installing it.

## Quick Example

Once installed, ask your agent to scan a skill before installing it. The scanner outputs structured JSON:


```json
{
  "scan_id": "f47ac10b-...",
  "risk_score": 80,
  "risk_level": "HIGH",
  "recommendation": "BLOCK",
  "findings": [
    {
      "type": "regex",
      "description": "AWS access key pattern detected",
      "severity": "HIGH",
      "evidence": "Matched 'Credential_AWS_Access_Key' at offset 342: AKIAIOSFODNN7EXAMPLE"
    },
    {
      "type": "regex",
      "description": "Data exfiltration to webhook.site detected",
      "severity": "CRITICAL",
      "evidence": "Matched 'Exfil_Webhook_Site' at offset 891: webhook.site/abc123"
    }
  ]
}
```

## What It Catches

37 detection patterns across 4 threat categories:

- **Credential theft** — AWS, GitHub, Stripe, OpenAI, Anthropic, Supabase, database connection strings, crypto private keys, and 30+ more secret formats
- **Data exfiltration** — Discord/Slack/Telegram webhooks, paste services, file drop services, DNS tunneling
- **Dangerous commands** — Reverse shells, container escape, privilege escalation, SSH key injection, PowerShell attacks, deserialization
- **Obfuscation** — Base64 chains, hex encoding, eval+encoding combos, unicode escape sequences

Full pattern list: [`skills/skills-audit/references/DETECTION-COVERAGE.md`](skills/skills-audit/references/DETECTION-COVERAGE.md)

## Full MCP Server

For CI/CD pipelines, marketplace scanning, and centralized rule updates, use the Shieldon MCP server:

```json
{
  "mcpServers": {
    "shieldon": {
      "url": "https://api.shieldon.dev/mcp"
    }
  }
}
```

The skill and MCP server produce identical results. The skill runs locally with zero dependencies; the MCP server adds centralized rule updates, future LLM-assisted scanning, and on-chain attestations.

More at [shieldon.dev](https://shieldon.dev)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Skills must address a threat vector in the AI agent ecosystem.

## License

[MIT](LICENSE)
