# IAM-Escalix

**AI-driven privilege escalation path discovery for cloud IAM.**

IAM-Escalix analyzes AWS IAM and Azure RBAC configurations with a large language
model and reports the paths by which a user could gain privileges they should not
have - along with risk explanations and mitigations.

Analyses AWS IAM and Azure RBAC configurations with a large language model and
reports the paths by which a principal could gain privileges it should not have.
Runs against **any OpenAI-compatible LLM backend** (OpenCode, OpenRouter,
Ollama, OpenAI) and supports fully offline analysis of stored IAM snapshots.

## Features

- Identifies potential privilege escalation paths in **AWS IAM** policies (Azure RBAC ported, best-effort)
- Works with **OpenCode, OpenRouter, local Ollama, or OpenAI** - switch with `--provider`
- **Offline mode**: analyze a stored policy snapshot with no cloud credentials
- Returns escalation paths, risks and mitigations as **JSON**, saved to a report file

## Installation

```powershell
git clone <your-fork-url> IAM-Escalix
cd IAM-Escalix
uv venv --python 3.11          # or: python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Configure a provider key (copy `.env.example` to `.env`):

```powershell
Copy-Item .env.example .env
# edit .env and set the key for the provider you plan to use
```

## Usage

### 1. Offline mode (no cloud account needed)

```powershell
iam-escalix --provider opencode --platform AWS `
  --policies-file examples/sample_policies.json `
  --output reports/opencode-deepseek.json
```

The `--policies-file` accepts a JSON snapshot shaped like the data collected from
live AWS accounts: `{ "<user-arn>": { "Policy": [ { "<policy-arn>": {...document...} } ] } }`.
See `examples/sample_policies.json` for a working specimen and
`examples/expected_paths.md` for its ground truth.

### 2. Live AWS analysis

Requires IAM read access on a **sandbox** account. Minimum permissions:
`iam:GetAccountAuthorizationDetails`, `iam:GetPolicy`, `iam:GetPolicyVersion`,
`iam:GetUser`. The `IAMReadOnlyAccess` managed policy covers all of these.

```powershell
# via AWS CLI profile (recommended; keeps secrets out of the CLI)
iam-escalix --provider opencode --platform AWS --profile sandbox --output reports/aws-sandbox.json

# or via explicit keys (goes into shell history - avoid on shared systems)
iam-escalix --provider opencode --platform AWS -k AKIA... -s <secret> --output reports/aws.json
```

### Providers

| Provider | `--provider` | API key env var | Default model |
|---|---|---|---|
| OpenCode Console | `opencode` | `OPENCODE_API_KEY` | `deepseek-v4.1-flash-free` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `nvidia/nemotron-3-super-120b-a12b:free` |
| Ollama (local) | `ollama` | none | `qwen2.5:7b-instruct` |
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4o-mini` |

Override the model any time with `--model <id>`.

### Output

`--output <file>.json` writes a report containing the request metadata
(provider, model, timestamp, prompt SHA-256), the **raw model answer**, and the
**parsed JSON** when parsing succeeded. `--save-prompt` additionally stores the
exact prompt sent to the model (may contain sensitive policy data - use with care).

## Security notes

- **Never run against a production account.** Use a dedicated sandbox account
  with read-only IAM permissions.
- Sending IAM policy JSON to a hosted LLM **is data egress**: with synthetic or
  sandbox data this is fine, but production policies may contain sensitive
  details. Prefer the offline mode, or a local Ollama model, for private data.
- Some free hosted models may train on your data. The OpenCode free models used
  by default (`deepseek-v4.1-flash-free`, `glm-5.3-flash-free`) are documented
  zero-retention by the OpenCode Console at time of writing - verify before use.
- API keys are read from environment variables, never logged, and should never
  be committed. Command-line `--api-key` overrides end up in shell history.

## License

GPL-3.0-or-later. See [LICENSE.md](LICENSE.md). See [NOTICE](NOTICE) for
third-party notices.

## Disclaimer

This tool is for educational and research purposes only, on systems you own or
are explicitly authorized to test. The authors assume no liability for misuse.
