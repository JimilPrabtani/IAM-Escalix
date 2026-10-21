"""IAM-Escalix command line interface.

Credentials come from environment variables / --api-key (never a positional
argument). Supports --provider/--model for OpenCode, OpenRouter, Ollama and
OpenAI; --policies-file / --policies-dir for offline analysis of stored IAM
snapshots; results are parsed and written to a JSON report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from main import __version__
from main.config import DEFAULT_TEMPERATURE, PROVIDERS, ProviderError, resolve_provider
from main.llm_client import LLMClient, LLMClientError


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="iam-escalix",
        description="IAM-Escalix - AI-driven privilege escalation path discovery for cloud IAM",
    )
    parser.add_argument("--version", action="version", version=f"iam-escalix {__version__}")

    # Model selection
    parser.add_argument(
        "--provider",
        choices=sorted(PROVIDERS),
        default="opencode",
        help="LLM backend to use (default: opencode)",
    )
    parser.add_argument("--model", type=str, default=None, help="Model id (defaults per provider)")
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key override (prefer the provider env var; keys passed on the "
        "command line end up in shell history and process listings)",
    )
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)

    # Platform selection
    parser.add_argument(
        "--platform",
        choices=["AWS", "AZURE"],
        default="AWS",
        help="Platform to analyze (AWS or AZURE)",
    )

    # Offline mode (one or more snapshots; supports multiple audits)
    parser.add_argument(
        "--policies-file",
        nargs="+",
        default=None,
        help="Offline mode: analyze one or more stored IAM policy snapshots (JSON). "
        "Multiple files are audited in sequence (one report per file).",
    )
    parser.add_argument(
        "--policies-dir",
        type=str,
        default=None,
        help="Offline mode: audit every *.json snapshot in a directory (multiple audits).",
    )

    # Output
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write the full report (request metadata + raw + parsed answer) to this JSON file",
    )
    parser.add_argument(
        "--save-prompt",
        action="store_true",
        help="Also save the generated prompt alongside the report (may contain sensitive data)",
    )

    # Platform-specific arguments
    aws_group = parser.add_argument_group("AWS Options")
    aws_group.add_argument("-k", "--aws-key", type=str, help="AWS Access Key")
    aws_group.add_argument("-s", "--aws-secret", type=str, help="AWS Secret Key")
    aws_group.add_argument("-P", "--profile", help="AWS CLI profile name")

    azure_group = parser.add_argument_group("Azure Options")
    azure_group.add_argument("-u", "--username", type=str, help="Azure Username")
    azure_group.add_argument("-p", "--password", type=str, help="Azure Password")
    azure_group.add_argument("-t", "--tenant-id", type=str, help="Azure Tenant ID")

    args = parser.parse_args(argv)
    if args.platform == "AZURE" and not args.policies_file and not (args.username and args.password and args.tenant_id):
        parser.error("--platform AZURE requires --username, --password and --tenant-id "
                     "(or use --policies-file for offline mode)")
    return args


def extract_json(text: str | None):
    """Best-effort extraction of a JSON object from an LLM answer.

    Tries, in order: materialized ```json fences, the whole text, and the
    span between the first '{' and the last '}'. Returns (parsed, ok).
    """
    if not text:
        return None, False

    target = text.strip()
    candidates: list[str] = []
    candidates.extend(match.strip() for match in re.findall(r"```(?:json)?\s*(.*?)```", target, flags=re.DOTALL))
    candidates.append(target)
    if "{" in target and "}" in target:
        candidates.append(target[target.index("{") : target.rindex("}") + 1])

    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            return json.loads(candidate), True
        except json.JSONDecodeError:
            continue
    return None, False


def build_prompt(args: argparse.Namespace, policies_file: str | None = None):
    """Collect IAM data and build the analysis prompt. Returns (prompt, mode)."""
    pf = policies_file
    if pf is None and args.policies_file:
        pf = args.policies_file[0]
    if pf:
        from cloud.fixture import Fixture

        return Fixture(pf).start(), "offline"

    if args.platform == "AZURE":
        from cloud.azure import Azure  # lazy: needs adal + network

        client = Azure(username=args.username, password=args.password, tenant_id=args.tenant_id)
        return client.start(), "live"

    from cloud.aws import AWS

    return AWS(args=args).start(), "live"


def resolve_audit_files(args: argparse.Namespace) -> list[str]:
    """Resolve the list of offline snapshot files to audit (may be empty)."""
    files: list[str] = []
    if args.policies_dir:
        d = Path(args.policies_dir)
        if not d.is_dir():
            raise FileNotFoundError(f"Policies directory not found: {d}")
        files.extend(str(p) for p in sorted(d.glob("*.json")))
    if args.policies_file:
        files.extend(args.policies_file)
    # de-duplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for f in files:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def run_one(args, policies_file, provider, model, api_key, output_path):
    """Run a single audit (online or offline) and write its report. Returns exit code."""
    try:
        prompt, mode = build_prompt(args, policies_file=policies_file)
    except FileNotFoundError as exc:
        print(f"[error] {exc}")
        return 1
    except Exception as exc:
        print(f"[error] Failed to collect IAM data: {exc}")
        return 1

    prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    print(f"[*] prompt built (mode={mode}, {len(prompt):,} chars, sha256={prompt_sha256[:12]}...)")

    llm = LLMClient(
        model=model,
        api_key=api_key,
        base_url=provider.base_url,
        temperature=args.temperature,
    )

    try:
        answer = llm.ask(prompt)
    except LLMClientError as exc:
        print(f"[error] {exc}")
        return 1

    parsed, parse_ok = extract_json(answer)

    paths_found = len(parsed.get("paths", [])) if parse_ok and isinstance(parsed, dict) else None
    if parse_ok:
        print(f"[+] valid JSON received ({paths_found} escalation path(s))")
    else:
        print("[!] model response could not be parsed as JSON; raw answer preserved in report")

    header = "--- model answer (parsed) ---" if parse_ok else "--- model answer (raw) ---"
    print("\n" + header)
    if parse_ok and isinstance(parsed, dict):
        print(json.dumps(parsed, indent=2))
    else:
        print(answer)

    report = {
        "tool": "iam-escalix",
        "version": __version__,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "provider": provider.name,
        "model": model,
        "temperature": args.temperature,
        "platform": args.platform,
        "mode": mode,
        "policies_file": policies_file,
        "prompt_sha256": prompt_sha256,
        "raw_response": answer,
        "parsed": parsed,
        "parse_ok": parse_ok,
    }
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[*] report written to {output_path}")

    if args.save_prompt:
        prompt_path = output_path.with_suffix(".prompt.txt")
        prompt_path.write_text(prompt, encoding="utf-8")
        print(f"[*] prompt written to {prompt_path}")

    return 0 if parse_ok else 2


def main(argv=None) -> int:
    args = parse_args(argv)

    try:
        provider, model, api_key = resolve_provider(args.provider, args.model, args.api_key)
    except ProviderError as exc:
        print(f"[error] {exc}")
        return 1

    print(f"[*] provider={provider.name} model={model} endpoint={provider.base_url or 'default'}")

    # Resolve the set of offline snapshots to audit (empty => live platform).
    try:
        audit_files = resolve_audit_files(args)
    except FileNotFoundError as exc:
        print(f"[error] {exc}")
        return 1

    if not audit_files:
        # Single live audit.
        rc = run_one(args, None, provider, model, api_key, args.output or "reports/live.json")
        return rc

    # Multiple audits: one report per snapshot.
    if len(audit_files) == 1 and args.output:
        targets = [(audit_files[0], args.output)]
    else:
        out_dir = Path(args.output) if args.output else Path("reports")
        targets = [(f, str(out_dir / (Path(f).stem + ".json"))) for f in audit_files]

    overall = 0
    for policies_file, output_path in targets:
        print(f"\n===== auditing {policies_file} =====")
        rc = run_one(args, policies_file, provider, model, api_key, output_path)
        if rc != 0:
            overall = rc
    return overall


if __name__ == "__main__":
    sys.exit(main())
