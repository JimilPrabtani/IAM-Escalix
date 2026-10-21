"""Colored ASCII banner and command reference for IAM-Escalix.

Printed on startup so users see the tool identity and the scan commands
without having to consult the README.
"""

from __future__ import annotations

import os
import sys

_ART = r"""
  ___  ___  _   _  ___  ___  ___  _   _  ___
 |_ _||   \| | | |/ __|| __|| __|| | | || __|
  | | | |) | |_| |\__ \| _| | _| | |_| || _|
  | | |___/ \___/ |___/|___||___| \___/ |___|
"""

_TAGLINE = "Escalix - AI-driven privilege escalation path discovery for cloud IAM"

_COMMANDS = """Scan commands:
  escalix --provider openrouter --platform AWS --policies-file <snapshot.json> --output <report.json>
  escalix --policies-dir <dir> --output <dir>        (audit every *.json in a directory)
  escalix --provider ollama --platform AWS --policies-file <snapshot.json>   (offline, no API key)
  escalix --provider openai --platform AWS -P <aws-profile> --output <report.json>

Options:
  --model <id>        override the provider default model
  --temperature <f>   sampling temperature (default 0.1)
  --save-prompt       also write the exact prompt sent to the model
  --version / --help  version and usage
"""


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stderr.isatty()
    except Exception:
        return False


def print_banner() -> None:
    """Print the colored banner + command reference to stderr."""
    if _color_enabled():
        cyan = "\x1b[36m"
        magenta = "\x1b[35;1m"
        yellow = "\x1b[33m"
        dim = "\x1b[2m"
        reset = "\x1b[0m"
    else:
        cyan = magenta = yellow = dim = reset = ""

    out = sys.stderr
    out.write(f"{cyan}{_ART}{reset}")
    out.write(f"{magenta}  {_TAGLINE}{reset}\n")
    out.write(f"{dim}  GPL-3.0-or-later | reports are written as JSON{reset}\n\n")
    out.write(f"{yellow}{_COMMANDS}{reset}\n")
    out.flush()
