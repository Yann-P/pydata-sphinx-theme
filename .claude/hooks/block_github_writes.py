#!/usr/bin/env python3
"""PreToolUse hook that blocks Bash commands which push to a protected branch
or post comments and reviews on GitHub issues and pull requests.

Everything else passes through, including read-only ``gh api`` calls and
``gh api`` writes that don't touch comments, reviews or a protected branch.
This is a guardrail, not a security boundary: a branch ruleset on GitHub is
what makes pushing to main impossible.
"""

import json
import os
import re
import shlex
import subprocess
import sys


PROTECTED_BRANCHES = {"main", "master"}

SEPARATOR_CHARS = set("();|&\n")
PREFIX_COMMANDS = {"command", "exec", "time", "nohup", "sudo", "env"}
SHELLS = {"bash", "sh", "zsh", "dash"}

# Options that take a value, so the next argument isn't a positional one.
GIT_GLOBAL_VALUE_OPTS = set("-C -c --git-dir --work-tree --namespace".split())
GIT_PUSH_VALUE_OPTS = set("--repo -o --push-option --receive-pack --exec".split())
GH_API_VALUE_OPTS = set(
    "-X --method -f --raw-field -F --field -H --header --input -q --jq -t --template"
    " --cache --hostname -p --preview".split()
)
GH_API_FIELD_OPTS = set("-f --raw-field -F --field".split())
GH_PR_MERGE_VALUE_OPTS = set(
    "-b --body -F --body-file -t --subject --match-head-commit -A --author-email"
    " -R --repo".split()
)

HEREDOC = re.compile(
    r"(<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\2)([^\n]*\n)(?:.*?\n)??[ \t]*\3[ \t]*(?=\n|$)",
    re.S,
)
COMMENT_PATH = re.compile(r"/(comments|replies)(/|$)|/pulls/\d+/reviews(/|$)")
REACTION_PATH = re.compile(r"/reactions(/\d+)?$")
PR_MERGE_PATH = re.compile(r"/repos/([^/]+/[^/]+)/pulls/(\d+)/merge$")
CONTENTS_PATH = re.compile(r"/contents(/|$)")
REF_PATH = re.compile(r"/git/refs/heads/(.+)$")
COMMENT_MUTATION = re.compile(
    r"\b(add\w*Comment|update\w*Comment|\w*PullRequestReview\w*"
    r"|mergePullRequest|enablePullRequestAutoMerge)\b"
)
BRANCH_MUTATION = re.compile(r"\b(createCommitOnBranch|updateRefs?|mergeBranch)\b")
PROTECTED_MENTION = re.compile(r"\b(%s)\b" % "|".join(PROTECTED_BRANCHES))
UNCHECKED_BASE = "a base branch that could not be checked"


class Blocked(Exception):
    """The command would push to a protected branch or post on GitHub."""


def run(args, cwd):
    """Return the stripped stdout of a command, or None if it fails."""
    try:
        result = subprocess.run(
            args, cwd=cwd, capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def split_commands(command):
    """Split a shell command line into the argv of each simple command."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    tokens = list(lexer)
    commands, current, i = [], [], 0
    while i < len(tokens):
        token = tokens[i]
        # The lexer groups runs of punctuation, such as ";\n" or ">&", into one token.
        if token and set(token) <= SEPARATOR_CHARS:
            if current:
                commands.append(current)
            current = []
        elif token and set(token) <= SEPARATOR_CHARS | set("<>"):
            # Redirection: drop the operator, its target and any fd number before it.
            if current and current[-1].isdigit():
                current.pop()
            i += 1
        else:
            current.append(token)
        i += 1
    if current:
        commands.append(current)
    return commands


def check_shell(command, cwd):
    """Check every simple command in a shell command line."""
    # Heredoc bodies are data, and their stray quotes would break the lexer.
    command = HEREDOC.sub(r"\1\4", command)
    try:
        commands = split_commands(command)
    except ValueError:
        if re.search(r"\bgit\b.*\bpush\b|\bgh\s+(api|pr|issue|repo)\b", command):
            raise Blocked(
                "couldn't parse this command to check it; split it into simpler ones"
            ) from None
        return
    for argv in commands:
        cwd = check_command(argv, cwd)


def check_command(argv, cwd):
    """Check one simple command and return the working directory after it."""
    while argv and (re.match(r"^[A-Za-z_]\w*=", argv[0]) or argv[0] in PREFIX_COMMANDS):
        argv = argv[1:]
        while argv and argv[0].startswith("-"):
            argv = argv[1:]
    if not argv:
        return cwd
    program = os.path.basename(argv[0].lstrip("`"))
    if program == "cd":
        return os.path.join(cwd, os.path.expanduser(argv[1] if len(argv) > 1 else "~"))
    if program == "eval":
        check_shell(" ".join(argv[1:]), cwd)
    elif program in SHELLS and "-c" in argv[1:-1]:
        check_shell(argv[argv.index("-c") + 1], cwd)
    elif program == "git":
        check_git(argv[1:], cwd)
    elif program == "gh":
        check_gh(argv[1:], cwd)
    return cwd


def current_branch(cwd):
    """Return the checked-out branch, or None on a detached HEAD."""
    return run(["git", "symbolic-ref", "--short", "-q", "HEAD"], cwd)


def check_git(args, cwd):
    """Block a ``git push`` that would update a protected branch."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            cwd = os.path.join(cwd, args[i + 1])
        i += 2 if args[i] in GIT_GLOBAL_VALUE_OPTS else 1
    if i >= len(args) or args[i] != "push":
        return

    rest, positional, explicit_repo, j = args[i + 1 :], [], False, 0
    while j < len(rest):
        arg = rest[j]
        if arg == "--":
            positional += rest[j + 1 :]
            break
        if arg in ("--all", "--mirror", "--branches"):
            raise Blocked(f"`git push {arg}` would also push main")
        if arg.startswith("--repo"):
            explicit_repo = True
        if arg in GIT_PUSH_VALUE_OPTS:
            j += 2
            continue
        if not arg.startswith("-"):
            positional.append(arg)
        j += 1

    refspecs = positional if explicit_repo else positional[1:]
    if not refspecs:
        pushed = run(
            ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{push}"], cwd
        )
        remote_branch = pushed.split("/", 1)[1] if pushed and "/" in pushed else None
        destinations = [remote_branch or current_branch(cwd)]
    else:
        destinations = []
        for refspec in refspecs:
            refspec = refspec.lstrip("+")
            if refspec == ":":
                raise Blocked("`git push <remote> :` pushes every matching branch")
            destination = refspec.split(":", 1)[1] if ":" in refspec else refspec
            if destination in ("HEAD", "@"):
                destination = current_branch(cwd)
            destinations.append(destination)
    for destination in destinations:
        branch = (destination or "").removeprefix("refs/heads/")
        if branch in PROTECTED_BRANCHES:
            raise Blocked(f"this `git push` updates {branch}; use a feature branch")


def check_gh(args, cwd):
    """Block ``gh`` subcommands that comment, review, or write to main."""
    if args and args[0] == "api":
        return check_gh_api(args[1:], cwd)
    if len(args) < 2 or args[0] not in ("pr", "issue", "repo"):
        return
    group, action, rest = args[0], args[1], args[2:]
    if group in ("pr", "issue") and action == "comment":
        raise Blocked(f"`gh {group} comment` posts a comment")
    if (
        group in ("pr", "issue")
        and action in ("close", "reopen")
        and any(a in ("-c", "--comment") or a.startswith("--comment=") for a in rest)
    ):
        raise Blocked(f"`gh {group} {action} --comment` posts a comment")
    if group == "pr" and action == "review":
        raise Blocked("`gh pr review` posts a review")
    if group == "pr" and action == "merge":
        check_gh_pr_merge(rest, cwd)
    if group == "repo" and action == "sync":
        check_gh_repo_sync(rest)


def check_gh_pr_merge(args, cwd):
    """Block ``gh pr merge`` unless the PR's base branch isn't protected."""
    positional, repo, i = [], [], 0
    while i < len(args):
        if args[i] in GH_PR_MERGE_VALUE_OPTS:
            if args[i] in ("-R", "--repo"):
                repo = ["-R", *args[i + 1 : i + 2]]
            i += 2
            continue
        if not args[i].startswith("-"):
            positional.append(args[i])
        i += 1
    view = ["gh", "pr", "view", *positional[:1], *repo, "--json", "baseRefName"]
    base = run([*view, "--jq", ".baseRefName"], cwd)
    if base is None or base in PROTECTED_BRANCHES:
        raise Blocked(f"`gh pr merge` merges into {base or UNCHECKED_BASE}")


def check_gh_repo_sync(args):
    """Block ``gh repo sync`` of a GitHub repository's protected branch."""
    positional, branch, i = [], None, 0
    while i < len(args):
        if args[i] in ("-b", "--branch", "-s", "--source"):
            if args[i] in ("-b", "--branch") and i + 1 < len(args):
                branch = args[i + 1]
            i += 2
            continue
        if not args[i].startswith("-"):
            positional.append(args[i])
        i += 1
    # Without a destination repository, `gh repo sync` only updates the local branch.
    if positional and (branch is None or branch in PROTECTED_BRANCHES):
        raise Blocked(f"`gh repo sync` updates {branch or 'the default branch'}")


def read_file(path, cwd):
    """Return a file's contents, or None for stdin or an unreadable file."""
    if path == "-":
        return None
    try:
        with open(os.path.join(cwd, path)) as f:
            return f.read()
    except OSError:
        return None


def check_gh_api(args, cwd):
    """Block ``gh api`` writes to comments, reviews or a protected branch."""
    method, endpoint, fields, input_file, i = None, None, {}, None, 0
    while i < len(args):
        arg, option, value = args[i], args[i], None
        if arg.startswith("--") and "=" in arg:
            option, value = arg.split("=", 1)
        elif re.match(r"^-[XfFHqtp].", arg):
            option, value = arg[:2], arg[2:]
        if option in GH_API_VALUE_OPTS:
            if value is None:
                value = args[i + 1] if i + 1 < len(args) else ""
                i += 1
            if option in ("-X", "--method"):
                method = value.upper()
            elif option in GH_API_FIELD_OPTS:
                key, _, field_value = value.partition("=")
                fields[key] = field_value
            elif option == "--input":
                input_file = value
        elif not arg.startswith("-") and endpoint is None:
            endpoint = arg
        i += 1
    if endpoint is None:
        return

    path = re.sub(r"^https?://[^/]+/", "", endpoint).split("?", 1)[0].strip("/")
    path = "/" + path
    body = fields
    if input_file is not None:
        try:
            body = json.loads(read_file(input_file, cwd) or "")
        except ValueError:
            body = None

    if path.endswith("/graphql"):
        if input_file is not None:
            text = read_file(input_file, cwd)
        else:
            query = fields.get("query", "")
            text = read_file(query[1:], cwd) if query.startswith("@") else query
            text = text and text + " " + json.dumps(fields)
        if text is None:
            raise Blocked("couldn't read this GraphQL request; pass the query inline")
        if re.search(r"\bmutation\b", text):
            if COMMENT_MUTATION.search(text):
                raise Blocked("this GraphQL mutation comments, reviews or merges")
            if BRANCH_MUTATION.search(text) and PROTECTED_MENTION.search(text):
                raise Blocked("this GraphQL mutation writes to main")
        return

    method = method or ("POST" if fields or input_file is not None else "GET")
    if method in ("GET", "HEAD"):
        return

    def body_field(key):
        value = body.get(key) if isinstance(body, dict) else None
        return value.removeprefix("refs/heads/") if isinstance(value, str) else None

    request = f"`gh api -X {method} {endpoint}`"
    if COMMENT_PATH.search(path) and not REACTION_PATH.search(path):
        raise Blocked(f"{request} creates, edits or deletes a comment or review")
    merge = PR_MERGE_PATH.search(path)
    if merge:
        pull = f"repos/{merge[1]}/pulls/{merge[2]}"
        base = run(["gh", "api", pull, "--jq", ".base.ref"], cwd)
        if base is None or base in PROTECTED_BRANCHES:
            raise Blocked(f"{request} merges into {base or UNCHECKED_BASE}")
        return

    ref = REF_PATH.search(path)
    if CONTENTS_PATH.search(path):
        key, branch = "branch", body_field("branch")
    elif ref:
        key, branch = "ref", ref[1]
    elif path.endswith("/git/refs"):
        key, branch = "ref", body_field("ref")
    elif path.endswith("/merges"):
        key, branch = "base", body_field("base")
    elif path.endswith("/merge-upstream"):
        key, branch = "branch", body_field("branch")
    else:
        return
    if branch is None or branch in PROTECTED_BRANCHES:
        target = branch or "the default branch"
        raise Blocked(f"{request} writes to {target}; pass -f {key}=<feature-branch>")


def main():
    """Read the hook payload and exit 2 to block the command."""
    payload = json.load(sys.stdin)
    if payload.get("tool_name") != "Bash":
        return 0
    command = payload.get("tool_input", {}).get("command", "")
    try:
        check_shell(command, payload.get("cwd") or os.getcwd())
    except Blocked as blocked:
        hook = ".claude/hooks/block_github_writes.py"
        print(f"Blocked by {hook}: {blocked}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
