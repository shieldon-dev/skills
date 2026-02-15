# Detection Coverage

Full list of 37 detection patterns across 4 threat categories.

## Credentials (12 rules)

| Rule | Severity | What it detects |
|------|----------|----------------|
| `Credential_AWS_Access_Key` | HIGH | AWS access key IDs (`AKIA` prefix) |
| `Credential_AWS_Secret_Reference` | HIGH | `AWS_SECRET_ACCESS_KEY`, `~/.aws/credentials` |
| `Credential_Private_Key_Block` | CRITICAL | PEM-encoded private keys (RSA, OpenSSH, EC, DSA) |
| `Credential_GitHub_Token` | HIGH | GitHub token prefixes: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` |
| `Credential_API_Key_Patterns` | MEDIUM | Stripe, Slack, SendGrid, Shopify, GitLab PAT, Mailgun |
| `Credential_Cloud_Provider_Keys` | HIGH | Google/GCP API keys, Azure Storage/SAS keys |
| `Credential_Package_Registry_Tokens` | HIGH | npm tokens, PyPI tokens |
| `Credential_Env_File_Access` | HIGH | `cat .env`, `.ssh/id_rsa`, `source .env`, `.npmrc`, `.netrc` |
| `Credential_LLM_Provider_Keys` | HIGH | OpenAI `sk-proj-`, Anthropic `sk-ant-api03-`, Hugging Face `hf_`, Replicate `r8_` |
| `Credential_Modern_SaaS_Tokens` | HIGH | Supabase, Vercel, Twilio, Discord bot, Telegram bot tokens |
| `Credential_Database_Connection_Strings` | HIGH | PostgreSQL, MongoDB, MySQL, Redis with embedded credentials |
| `Credential_Crypto_Private_Keys` | CRITICAL | EVM private keys, Solana keypair files/JSON, Bitcoin WIF keys |

## Exfiltration (10 rules)

| Rule | Severity | What it detects |
|------|----------|----------------|
| `Exfil_Webhook_Site` | CRITICAL | `webhook.site` references |
| `Exfil_Known_Paste_Services` | HIGH | Pastebin, hastebin, requestbin, pipedream, burpcollaborator |
| `Exfil_Ngrok_Tunnel` | HIGH | Ngrok tunnel endpoints |
| `Exfil_Curl_Post` | MEDIUM | `curl -X POST`, `wget --post-data` |
| `Exfil_DNS_Tunneling` | HIGH | DNS query patterns indicating tunneling (requires 2+ indicators) |
| `Exfil_Discord_Webhook` | CRITICAL | Discord webhook URLs |
| `Exfil_Telegram_Bot` | HIGH | Telegram Bot API endpoints |
| `Exfil_Slack_Webhook` | HIGH | Slack incoming webhook URLs |
| `Exfil_Modern_Drop_Services` | HIGH | transfer.sh, file.io, 0x0.st, gofile.io, anonfiles.com |
| `Exfil_HTTP_Client_Post` | MEDIUM | `requests.post()`, `axios.post()`, `fetch(...POST)`, `httpx.post()` |

## Dangerous Commands (10 rules)

| Rule | Severity | What it detects |
|------|----------|----------------|
| `Dangerous_Reverse_Shell` | CRITICAL | Bash, netcat, Python/Perl/PHP reverse shells |
| `Dangerous_System_Destruction` | CRITICAL | `rm -rf /`, `dd if=/dev/zero` |
| `Dangerous_Privilege_Escalation` | HIGH | `chmod 777`, SUID, NOPASSWD, `/etc/shadow` (requires 2+ indicators) |
| `Dangerous_Download_Execute` | CRITICAL | `curl \| bash`, `wget \| sh`, download-chmod-execute |
| `Dangerous_Cron_Persistence` | HIGH | Piped crontab writes, `/etc/cron` |
| `Dangerous_Code_Injection` | HIGH | `os.popen()`, `__import__('os')`, PHP webshells, `pickle.loads()`, `marshal.loads()` |
| `Dangerous_Container_Escape` | CRITICAL | Docker host root mount, nsenter into host PID namespace |
| `Dangerous_Docker_Socket_Access` | HIGH | `/var/run/docker.sock` access |
| `Dangerous_SSH_Key_Injection` | HIGH | Writes to `~/.ssh/authorized_keys` |
| `Dangerous_PowerShell_Execution` | HIGH | `Invoke-Expression`, `\| iex`, `DownloadString()`, encoded commands, execution policy bypass |

## Obfuscation (5 rules)

| Rule | Severity | What it detects |
|------|----------|----------------|
| `Obfuscation_Base64_Decode_Chain` | HIGH | `b64decode()`, `base64 -d`, `atob()`, `[Convert]::FromBase64String`, `Base64.decode64()` |
| `Obfuscation_Hex_Encoding` | MEDIUM | Long `\x` sequences, `bytes.fromhex()` |
| `Obfuscation_Eval_With_Encoding` | CRITICAL | `eval()`/`exec()` + base64/decode/compile |
| `Obfuscation_String_Concat_Evasion` | MEDIUM | `chr()` concatenation, `join(map(chr, ...))` |
| `Obfuscation_Unicode_Escape` | MEDIUM | 6+ consecutive `\uXXXX` escapes, `decode('unicode_escape')` |

## Scoring

| Severity | Points |
|----------|--------|
| LOW | 10 |
| MEDIUM | 20 |
| HIGH | 30 |
| CRITICAL | 50 |

Total score is capped at 100. Any CRITICAL finding forces the recommendation to BLOCK.
