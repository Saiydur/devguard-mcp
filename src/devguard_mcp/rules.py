"""Catalogue of every rule: what it means, how serious it is, and what to do about it."""

from __future__ import annotations

from dataclasses import dataclass

from devguard_mcp.models import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    campaign: str
    description: str
    remediation: str


_RULES = (
    Rule(
        "DG-PR-001",
        "Known payload marker in source code",
        Severity.HIGH,
        "polinrider",
        "A string that appears in known PolinRider loaders (obfuscator identifiers, stage tags, "
        "XOR keys, stage-URL paths) was found in a file.",
        "Do not run the project. Remove the injected code, then follow `recovery_checklist`: "
        "the machine that last ran this code may be compromised.",
    ),
    Rule(
        "DG-PR-002",
        "Weak payload marker",
        Severity.MEDIUM,
        "polinrider",
        "A pattern such as `global['!']` or `global.i = 'A9-...'` that the loaders use to pass "
        "state. Rarely legitimate, but not unique, so it is rated lower on its own.",
        "Inspect the surrounding code. If it sits next to obfuscated or whitespace-padded code, "
        "treat as DG-PR-001.",
    ),
    Rule(
        "DG-PR-003",
        "Payload hidden after whitespace padding",
        Severity.HIGH,
        "polinrider",
        "A line longer than 3,000 characters contains a run of 100+ spaces or tabs followed by "
        "more code. Attackers append the payload to config files (postcss, tailwind, eslint, "
        "next, vite) after padding so it is off-screen in an editor.",
        "Open the file with word wrap or `awk 'length>3000'`, remove everything after the "
        "padding, and treat the machine as exposed.",
    ),
    Rule(
        "DG-PR-004",
        "package.json script runs a large local JavaScript file",
        Severity.HIGH,
        "polinrider",
        "A script such as `node api.js && next dev` runs a sizeable or obfuscated file before "
        "the real command. This executes the payload on every dev/build/start.",
        "Remove the prefix and delete the file after confirming it is not your code.",
    ),
    Rule(
        "DG-PR-005",
        "VS Code task runs automatically and looks malicious",
        Severity.HIGH,
        "polinrider",
        "A task with `runOn: folderOpen` runs a downloader, a shell, or `node` against a "
        "non-script file (for example a fake font). It executes when the folder is opened in a "
        "trusted VS Code workspace.",
        "Delete the task, delete the file it points to, and open unknown repos in Restricted Mode.",
    ),
    Rule(
        "DG-PR-006",
        "VS Code task runs automatically",
        Severity.LOW,
        "polinrider",
        "A task with `runOn: folderOpen` exists. Often legitimate (dev servers), but it is a "
        "known execution vector.",
        "Confirm you wrote it and that it only runs code you trust.",
    ),
    Rule(
        "DG-PR-007",
        "Font file is not a font",
        Severity.HIGH,
        "polinrider",
        "A .ttf/.otf/.woff/.woff2/.eot file does not start with a valid font header. PolinRider "
        "hides JavaScript in such files and runs it with `node`.",
        "Delete the file and any task or script that references it.",
    ),
    Rule(
        "DG-PR-008",
        "Known attacker helper script",
        Severity.HIGH,
        "polinrider",
        "`temp_auto_push.bat` amends the latest commit with the payload, rewinds the system "
        "clock to hide the change, and force-pushes. Its presence means a machine that pushed "
        "this repo was compromised.",
        "Delete it, rotate GitHub credentials, and audit recent force-pushes.",
    ),
    Rule(
        "DG-PR-009",
        "Heavily obfuscated JavaScript",
        Severity.MEDIUM,
        "generic",
        "Very many `_0x....` identifiers or `\\u00XX` escapes. Obfuscation is not malicious by "
        "itself (some vendors ship it), so this needs human review.",
        "Check who added the file and why; compare with the upstream project.",
    ),
    Rule(
        "DG-HS-001",
        "Twin commits (same author, time and message; different content)",
        Severity.MEDIUM,
        "polinrider",
        "Two commits share author, author-time and subject but have different trees. This is the "
        "fingerprint of a rewritten commit: the clean original and an amended copy that adds "
        "malware.",
        "Diff the twins; treat the added files as malicious and find which machine pushed them.",
    ),
    Rule(
        "DG-HS-002",
        "Committer timezone re-stamped",
        Severity.MEDIUM,
        "polinrider",
        "The committer timestamp equals the author timestamp but is written in a different "
        "timezone, by the same person. Normal workflows rarely do this; rewriting tools that "
        "reset the clock do.",
        "Compare against reflogs and CI history; investigate which machine rewrote the commits.",
    ),
    Rule(
        "DG-HS-003",
        "Earliest commit containing a payload marker",
        Severity.INFO,
        "polinrider",
        "Reports the oldest commit that adds a known marker. Commit dates are attacker-controlled "
        "and may be forged, so this shows *where* it is in history, not *when* it happened.",
        "Use it to find the files to clean; do not rely on the date.",
    ),
    Rule(
        "DG-GA-001",
        "Workflow file name used by GhostAction",
        Severity.MEDIUM,
        "ghostaction",
        "A workflow is named github_actions_security.yml, security-check.yml or "
        "security-audit.yml, names used by the campaign. They are also plausible legitimate names.",
        "Read the file. If you did not add it, remove it and rotate every secret it can read.",
    ),
    Rule(
        "DG-GA-002",
        "Workflow references a known attacker host",
        Severity.CRITICAL,
        "ghostaction",
        "The workflow mentions an IP address or domain used for secret exfiltration.",
        "Remove the workflow, revoke the credential that pushed it, rotate all secrets.",
    ),
    Rule(
        "DG-GA-003",
        "Workflow has an exfiltration job signature",
        Severity.HIGH,
        "ghostaction",
        "Contains the job id `send-secrets` or step names used by GhostAction.",
        "Remove the workflow and rotate all secrets the repository exposes to Actions.",
    ),
    Rule(
        "DG-GA-004",
        "Workflow posts secrets with curl",
        Severity.HIGH,
        "ghostaction",
        "A `curl` command sends `${{ secrets.X }}` values to a URL. Plain-HTTP or raw-IP targets "
        "are rated higher than HTTPS to a named host.",
        "Verify the destination; if unknown, treat the secrets as stolen and rotate them.",
    ),
    Rule(
        "DG-GA-005",
        "Workflow scans the full git history",
        Severity.MEDIUM,
        "ghostaction",
        "`git log -p --all` inside a workflow is how the Oct 2026 GhostAction variant harvests "
        "keys from history.",
        "Confirm it is intentional (secret scanners do this); otherwise remove it.",
    ),
    Rule(
        "DG-GA-006",
        "Workflow serialises every secret",
        Severity.MEDIUM,
        "ghostaction",
        "`toJSON(secrets)` exposes all repository secrets to a step.",
        "Reference only the specific secrets a step needs.",
    ),
    Rule(
        "DG-GA-007",
        "pull_request_target checks out untrusted code",
        Severity.MEDIUM,
        "ghostaction",
        "A `pull_request_target` workflow checks out the pull request head with access to "
        "secrets, allowing code from a fork to read them.",
        "Use `pull_request`, or never check out untrusted refs in privileged workflows.",
    ),
    Rule(
        "DG-GA-008",
        "Commit message used by GhostAction",
        Severity.MEDIUM,
        "ghostaction",
        "A commit message matches those used when GhostAction injects or updates its workflow, "
        "for example 'Add Github Actions Security workflow'.",
        "Inspect the commit's diff and author; if you did not make it, treat it as a compromise.",
    ),
    Rule(
        "DG-MC-001",
        "Malware persistence directory on this machine",
        Severity.CRITICAL,
        "polinrider",
        "`~/.node_modules` with `.npm-ws*` files is where the PolinRider runner is installed.",
        "Rebuild the machine from a clean OS image and rotate every credential from a clean "
        "device.",
    ),
    Rule(
        "DG-MC-002",
        "Suspicious node process",
        Severity.CRITICAL,
        "polinrider",
        "A `node -e` process that evals downloaded code or references a known marker is running.",
        "Disconnect from the network, kill it, and rebuild the machine.",
    ),
    Rule(
        "DG-MC-003",
        "Connection to a known attacker host",
        Severity.CRITICAL,
        "polinrider",
        "An open or recent connection to a known command-and-control address.",
        "Treat the machine as compromised.",
    ),
    Rule(
        "DG-MC-004",
        "Suspicious startup item",
        Severity.HIGH,
        "polinrider",
        "A launch agent, scheduled task, cron entry or autostart that references "
        "`.node_modules`, `node -e` or a known marker.",
        "Remove it and rebuild the machine.",
    ),
    Rule(
        "DG-MC-005",
        "Suspicious shell startup file",
        Severity.HIGH,
        "polinrider",
        "A shell rc/profile file references `.node_modules`, `node -e` or a known marker.",
        "Remove the line and rebuild the machine.",
    ),
    Rule(
        "DG-CR-001",
        "GitHub token stored in shell history",
        Severity.MEDIUM,
        "generic",
        "A personal access token appears in a shell history file (often from "
        "`git clone https://TOKEN@github.com/...`). Infostealers read these files.",
        "Revoke the token, delete the history line, and use `gh auth login` or SSH instead.",
    ),
    Rule(
        "DG-CR-002",
        "GitHub token embedded in a git remote URL",
        Severity.MEDIUM,
        "generic",
        "A repository's `.git/config` contains a token in the remote URL, stored in plaintext.",
        "Revoke the token and run `git remote set-url origin <clean-url>`.",
    ),
    Rule(
        "DG-CR-003",
        "Broad GitHub token scopes",
        Severity.MEDIUM,
        "ghostaction",
        "The current GitHub CLI token can write workflows or administer repositories. "
        "GhostAction uses stolen tokens with the `workflow` scope to plant secret-stealing "
        "workflows.",
        "Use fine-grained tokens limited to required repos and permissions; avoid `workflow`.",
    ),
    Rule(
        "DG-GH-001",
        "Repository Actions secrets exposure",
        Severity.INFO,
        "ghostaction",
        "Lists secret *names* (never values) that a malicious workflow in this repo could read.",
        "If a token with write access was ever exposed, rotate these secrets.",
    ),
)

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def get_rule(rule_id: str) -> Rule | None:
    return RULES.get(rule_id.strip().upper())


def rules_markdown() -> str:
    """Render the catalogue as Markdown. ``docs/RULES.md`` is generated from this."""
    lines = [
        "# Rule reference",
        "",
        "<!-- Generated by `devguard-mcp rules --markdown`. Do not edit by hand. -->",
        "",
        "| ID | Severity | Campaign | Title |",
        "|----|----------|----------|-------|",
    ]
    lines += [
        f"| [{r.id}](#{r.id.lower()}) | {r.severity.name.lower()} | {r.campaign} | {r.title} |"
        for r in RULES.values()
    ]
    for rule in RULES.values():
        lines += [
            "",
            f"## {rule.id}",
            "",
            f"**{rule.title}** (severity: {rule.severity.name.lower()}, campaign: {rule.campaign})",
            "",
            rule.description,
            "",
            f"**What to do:** {rule.remediation}",
        ]
    return "\n".join(lines) + "\n"
