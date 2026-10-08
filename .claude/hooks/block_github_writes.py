#!/usr/bin/env python3
"""PreToolUse hook that stops Bash commands pushing to main or posting on GitHub.

It matches command text, so it's a rough guardrail with gaps: a branch ruleset
on GitHub is what actually protects main.
"""

import json
import re
import subprocess
import sys


def on_main(cwd):
    """Return whether the checked-out branch is main or master."""
    git = ["git", "branch", "--show-current"]
    branch = subprocess.run(git, cwd=cwd, capture_output=True, text=True).stdout
    return branch.strip() in ("main", "master")


payload = json.load(sys.stdin)
for part in re.split(r"&&|\|\||[;|\n]", payload["tool_input"].get("command", "")):
    part = part.strip()
    writes = re.search(r"\s(-[fFX]|--raw-field|--field|--input|--method)", part)
    writes = writes and not re.search(r"(-X|--method)[\s=]*GET", part)
    if re.match(r"git\s+push\b", part):
        blocked = re.search(r"\b(main|master)\b", part) or on_main(payload.get("cwd"))
    elif re.match(r"gh\s+(pr\s+(comment|review|merge)|issue\s+comment)\b", part):
        blocked = True
    elif re.match(r"gh\s+api\b", part) and writes:
        blocked = re.search(
            r"/(comments|replies|reviews)\b|mutation.*(Comment|Review|merge)"
            r"|heads/(main|master)\b|branch=(main|master)\b|/merges?\b"
            r"|/contents/(?!.*branch=)",
            part,
        )
    else:
        blocked = False
    if blocked:
        print(f"Blocked (push to main or GitHub post): {part}", file=sys.stderr)
        sys.exit(2)
