"""IAM-Escalix command line interface.

Modified from EscalateGPT (Tenable, GPL-3.0), 2026-10-21:
- the OpenAI API key is no longer a required positional argument; credentials
  come from environment variables / --api-key
- added --provider/--model for OpenCode, OpenRouter, Ollama and OpenAI
- added --policies-file for offline analysis of a stored IAM snapshot
- results are parsed and written to a JSON report instead of only being logged
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

    # Offline mode
    parser.add_argument(
        "--policies-file",
        type=str,
        default=None,
        help="Offline mode: analyze a stored IAM policy snapshot (JSON) instead of "
        "querying a live cloud account",
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
    if args.platform == "AWS" and not args.policies_file and not (
        args.profile or (args.aws_key and args.aws_secret)
    ):
        # Neither CLI credentials nor a profile: cloud.aws can still fall back
        # to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables.
        pass
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


def build_prompt(args: argparse.Namespace):
    """Collect IAM data and build the analysis prompt. Returns (prompt, mode)."""
    if args.policies_file:
        from cloud.fixture import Fixture

        return Fixture(args.policies_file).start(), "offline"

    if args.platform == "AZURE":
        from cloud.azure import Azure  # lazy: needs adal + network

        client = Azure(username=args.username, password=args.password, tenant_id=args.tenant_id)
        return client.start(), "live"

    from cloud.aws import AWS

    return AWS(args=args).start(), "live"


def main(argv=None) -> int:
    args = parse_args(argv)

    try:
        provider, model, api_key = resolve_provider(args.provider, args.model, args.api_key)
    except ProviderError as exc:
        print(f"[error] {exc}")
        return 1

    print(f"[*] provider={provider.name} model={model} endpoint={provider.base_url or 'default'}")

    try:
        prompt, mode = build_prompt(args)
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

    if args.output:
        report = {
            "tool": "iam-escalix",
            "version": __version__,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "provider": provider.name,
            "model": model,
            "temperature": args.temperature,
            "platform": args.platform,
            "mode": mode,
            "policies_file": args.policies_file,
            "prompt_sha256": prompt_sha256,
            "raw_response": answer,
            "parsed": parsed,
            "parse_ok": parse_ok,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[*] report written to {output_path}")

        if args.save_prompt:
            prompt_path = output_path.with_suffix(".prompt.txt")
            prompt_path.write_text(prompt, encoding="utf-8")
            print(f"[*] prompt written to {prompt_path}")

    return 0 if parse_ok else 2


if __name__ == "__main__":
    sys.exit(main())
