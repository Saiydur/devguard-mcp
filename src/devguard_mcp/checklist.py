"""Ordered recovery guidance. Static text: it never inspects or changes the machine."""

from __future__ import annotations

from typing import Any


def build_checklist(
    *,
    machine_compromised: bool = False,
    repos_infected: bool = False,
    workflows_suspect: bool = False,
) -> list[dict[str, Any]]:
    """Return recovery steps in the order they should be done.

    The order matters: credentials must be rotated from a clean device, otherwise the new
    credentials are exposed to the same malware.
    """
    steps: list[tuple[str, str]] = []

    if machine_compromised:
        steps.append(
            (
                "Stop using the affected machine for anything sensitive",
                "The PolinRider second stage is downloaded at runtime and can steal browser "
                "data, SSH keys, tokens and wallets. Do the rest of this list from a clean device.",
            )
        )

    if machine_compromised or workflows_suspect or repos_infected:
        steps.append(
            (
                "Revoke and rotate GitHub credentials (from a clean device)",
                "Change the password, enable a passkey or hardware-key 2FA, revoke all personal "
                "access tokens and authorised OAuth apps, delete SSH keys, then review Settings -> "
                "Security log for unknown sign-ins and token use.",
            )
        )
        steps.append(
            (
                "Rotate every secret the machine or workflows could read",
                "Everything in `.env` files, cloud and database credentials, deploy keys and SSH "
                "keys, npm/PyPI/Docker tokens, and every GitHub Actions secret in affected repos. "
                "Rotating secrets without revoking the GitHub credential is not enough: the "
                "attacker can re-inject a workflow.",
            )
        )

    if workflows_suspect:
        steps.append(
            (
                "Remove malicious workflows and review Actions history",
                "Delete the workflow files from every branch, check the Actions tab for runs that "
                "executed, and check recently added deploy keys, webhooks and collaborators.",
            )
        )

    if repos_infected:
        steps.append(
            (
                "Clean the repositories and block re-infection",
                "Use `plan_cleanup` to remove payloads and `node file.js &&` prefixes on every "
                "branch via normal commits. Enable branch protection (required reviews, no force "
                "pushes) and CODEOWNERS on `.github/workflows/`. Tell every collaborator: anyone "
                "with an infected clone can push the malware back.",
            )
        )

    if machine_compromised:
        steps.append(
            (
                "Rebuild the machine",
                "Back up source code only (not whole-disk images), erase and reinstall the "
                "operating system, and reinstall tools fresh. Cleaning by hand cannot prove the "
                "second stage left nothing behind.",
            )
        )

    steps.append(
        (
            "Reduce the chance of it happening again",
            "Scan unfamiliar repos before running `npm`/`pnpm`/`yarn`; open them in VS Code "
            "Restricted Mode or a devcontainer; use fine-grained GitHub tokens without the "
            "`workflow` scope; never put tokens in clone URLs; set Actions' default permissions to "
            "read-only and pin third-party actions to commit SHAs.",
        )
    )
    steps.append(
        (
            "Report it",
            "Tell GitHub's security team and the project owners whose repos were infected, and "
            "share indicators (not payloads) with OpenSourceMalware.",
        )
    )

    steps.append(
        (
            "Read the full recovery guide",
            "docs/RECOVERY.md in the devguard-mcp repository covers the reset vs cleanup decision, "
            "per-OS reset steps, what to back up, and the complete credential-rotation list.",
        )
    )
    return [
        {"order": i, "title": title, "detail": detail}
        for i, (title, detail) in enumerate(steps, start=1)
    ]
