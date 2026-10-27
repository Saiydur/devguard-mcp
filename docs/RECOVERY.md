# Recovery guide: you ran infected code

Read this if `devguard-mcp` reported findings, a collaborator warned you, GitHub shows commits you
did not make, or you ran or opened a project that contained the **PolinRider** implant or you
were hit by **GhostAction**.

> **Assume the worst until you can prove otherwise.** The malware downloads its real payload at
> runtime, so nobody (including this tool) can say exactly what it took. The goal is to (1) cut off
> the attacker, (2) rebuild a machine you can trust, and (3) rotate everything the old machine could
> read. Deleting a few files is *not* recovery.

**Do not use the infected machine to change passwords or tokens.** The malware can read what you
type and what you store. Use a different, trusted device (a phone is fine for the first steps).

## Contents

1. [Decide: reset or targeted cleanup](#1-decide-reset-or-targeted-cleanup)
2. [Cut off the attacker (from a clean device)](#2-cut-off-the-attacker-from-a-clean-device)
3. [Back up only what is safe](#3-back-up-only-what-is-safe)
4. [Reset the machine](#4-reset-the-machine) ([macOS](#macos) · [Windows](#windows) · [Linux](#linux))
5. [Rebuild safely](#5-rebuild-safely)
6. [Rotate credentials: the full list](#6-rotate-credentials-the-full-list)
7. [Clean your repositories and GitHub](#7-clean-your-repositories-and-github)
8. [If you cannot reset yet: best-effort containment](#8-if-you-cannot-reset-yet-best-effort-containment)
9. [Verify and monitor](#9-verify-and-monitor)
10. [Harden so it does not happen again](#10-harden-so-it-does-not-happen-again)
11. [Special cases and FAQ](#11-special-cases-and-faq)

---

## 1. Decide: reset or targeted cleanup

Run these from the infected machine only if it is safe to do so (read-only commands), or ask a
colleague to run them on a copy:

```bash
devguard-mcp machine            # runner, processes, connections, startup items, tokens in history
devguard-mcp scan path/to/project
```

| Situation | What it means | Do this |
|-----------|---------------|---------|
| `machine` shows **any critical finding** (`DG-MC-001`..`003`): runner files, a malicious `node -e` process, a connection to an attacker host | The payload ran and the runner is installed or was active | **Full reset** (section 4). No exceptions. |
| You **ran** the project (`npm`/`pnpm`/`yarn` `dev`, `build`, `start`, `install`, `node api.js`) or **opened it in an editor** (VS Code extensions load config files; auto-run tasks) and the scan shows PolinRider findings, even if `machine` is clean | Very likely executed. The runner may have been removed, moved, or not yet written | **Full reset** (recommended). If you truly cannot, follow section 8 and plan the reset soon. |
| Findings only in a repo you **never cloned, ran or opened** (for example you found it on GitHub) | The malware did not run on your machine | Clean the repository (section 7); rotate any token that could have pushed it |
| Findings were pushed to **your** repos but your machine looks clean | A token or a collaborator's machine did it | Revoke tokens and clean repos (sections 2 and 7); check collaborators' machines |
| GhostAction workflow found in a repo | Someone used a stolen token to plant it | Revoke that token first, then rotate secrets (sections 2, 6 and 7); look for the infostealer that leaked the token, which may be on *your* machine |
| Not sure | | Treat as the second row |

**Why reset instead of cleaning by hand?** The second stage can install anything: new startup
entries, browser extensions, modified shell files, SSH keys, remote-access tools. Manual cleanup
can only remove what you know to look for. In a real case, a machine cleaned by hand was
**re-infected within the hour** when the editor reopened the still-infected project.

**Employer or school device?** Stop and tell your security team *before* wiping. They may need the
disk for investigation and will own the credential rotation for company systems.

## 2. Cut off the attacker (from a clean device)

Do this **before** wiping, because the attacker may already hold working tokens, and a wipe does
not revoke them. Use a clean phone or computer.

1. **Disconnect the infected machine** from the network (Wi-Fi off, unplug Ethernet). Leave it on if
   you want to preserve evidence (see section 11); otherwise power it down.
2. **GitHub** (<https://github.com/settings/security>):
   - Change the password; turn on 2FA with a **passkey or security key**.
   - Sign out all sessions; open *Settings -> Sessions* and the *Security log* and note anything
     unfamiliar.
   - *Settings -> Developer settings*: revoke **every** personal access token (classic and
     fine-grained) and GitHub App/OAuth authorisation you do not recognise or no longer need.
   - *Settings -> SSH and GPG keys*: delete all keys; add new ones later from the rebuilt machine.
   - *Settings -> Applications*: revoke authorised OAuth apps (the GitHub CLI and VS Code can be
     re-authorised afterwards).
   - For every affected repo and org: *Deploy keys*, *Webhooks*, *Collaborators/teams*, and
     *Settings -> Secrets and variables -> Actions* (see section 6).
3. **Email and your password manager:** change the passwords and enable passkey or hardware-key 2FA.
   Email resets everything else, so it comes first.
4. Continue with the credential list in [section 6](#6-rotate-credentials-the-full-list).

Revoking the GitHub credentials is what stops GhostAction-style attacks; rotating only the
repository secrets is not enough, because the attacker can plant the workflow again.

## 3. Back up only what is safe

You are protecting your *work*, not the old machine's state. Copy the minimum, to an external drive
or a clean cloud folder.

**Back up**

- Source code folders **without** `node_modules`, build output, and `.env` files.
  For repos with a remote, the remote is your source of truth; you only need *uncommitted* work.
  `git status` and `git stash list` show what is not pushed.
- Documents, images and media you created (low risk; scan them later).

**Do not copy or restore**

| Item | Why |
|------|-----|
| A whole-disk backup, Time Machine / Migration Assistant, "restore from backup" | It brings the malware and its persistence back |
| `~/.ssh`, `~/.config/gh`, `~/.aws`, `~/.npmrc`, `~/.docker`, keychains, browser profiles, password-manager databases | They hold secrets the attacker may have copied; create new ones |
| `.env` files and `*.pem`/`*.key` | Recreate them with **new** secrets |
| Shell dotfiles (`.zshrc`, `.bashrc`, `.profile`), editor settings and extension folders | Common persistence locations; re-create by hand |
| Executables, installers, scripts you did not write, Office files with macros | Can carry the malware |
| `node_modules`, virtual environments, caches | Reinstall from lockfiles after the reset |

Before you use the backup, **scan the copy on the clean machine** (section 5) and never open its
folders in an editor first.

If you have unpushed commits, push them only from the rebuilt machine with fresh credentials, or
copy the repository folder and use `git bundle`/patches after scanning it.

## 4. Reset the machine

Choose the strongest option you can do. All of them delete the old user data, so finish sections
2 and 3 first.

### macOS

**Recommended: erase and reinstall macOS.**

1. Sign out of iCloud and Find My if you are able to (*System Settings -> your name -> Sign Out*).
2. Apple silicon or T2 Macs on a recent macOS: *System Settings -> General -> Transfer or Reset ->
   **Erase All Content and Settings***. This wipes user data and settings and keeps macOS.
3. For a deeper clean (also reinstalls the OS): boot to **Recovery** (Apple silicon: hold the power
   button until *Loading startup options*, choose *Options*; Intel: hold **Cmd+R** at startup), open
   **Disk Utility**, choose *View -> Show All Devices*, erase the internal disk (APFS), then choose
   **Reinstall macOS**.
4. At setup, create a **new** user. Do **not** use Migration Assistant. Sign in to Apple ID last.
5. Update macOS fully before installing anything else, and turn on FileVault and the firewall
   (*System Settings -> Privacy & Security / Network*).

### Windows

1. *Settings -> System -> Recovery -> **Reset this PC** -> Remove everything*. Choose **Cloud
   download** and **Clean data** when offered.
2. Strongest option: create Windows install media on a **clean** computer, boot from it, delete all
   partitions on the system drive, and install fresh.
3. After install: run Windows Update until it is current, confirm **Secure Boot** and **BitLocker /
   device encryption** are on, and keep Microsoft Defender enabled. Run a full Defender scan.
4. Create a new local or Microsoft account; do not sign in to browsers or apps until section 6 is
   done.

### Linux

1. Boot a live USB made on a clean computer.
2. Wipe the system disk (for example, delete all partitions and reinstall with full-disk
   encryption). Back up only what section 3 allows.
3. Reinstall, update everything, then re-create your user, SSH keys and dotfiles by hand.

### Hardware and firmware

A user-level malware like this does not normally survive an OS reinstall. If you have reason to
suspect firmware tampering (unexpected boot behaviour, a tampered device), use the manufacturer's
recovery tools or a service centre; Apple's *Apple Configurator* can revive/restore a Mac from a
second Mac.

## 5. Rebuild safely

1. Install the OS updates, then only the tools you need, from their official sources.
2. Install a password manager and sign in **last**, from a master password you changed in step 2.
3. Install `devguard-mcp` first, so you can scan before you run anything:
   ```bash
   pipx install /path/to/devguard-mcp      # or pip install into a virtualenv
   devguard-mcp --version
   ```
4. Clone your repositories **fresh from GitHub** (not from the backup), then scan each one *before*
   opening it in an editor or installing dependencies:
   ```bash
   git clone --no-checkout https://github.com/you/repo.git && cd repo
   git checkout -q main
   devguard-mcp scan . --fail-on low
   devguard-mcp history .
   ```
   Fix findings with the repository clean-up in section 7 *first*; only then `npm ci`.
5. Scan the backed-up copy of uncommitted work the same way before copying files into a clone.
6. Authenticate with **least privilege** (section 10): `gh auth login` with a narrow scope, a new
   SSH key with a passphrase.

## 6. Rotate credentials: the full list

Rotate **everything the old machine could read**, from a clean device, and assume the exposure
window starts when the project was first run. Work through this in order; tick items off.

| Priority | Item | What to do |
|----------|------|------------|
| 1 | Email and password manager | New passwords, passkey/hardware 2FA, sign out other sessions |
| 1 | **GitHub** | Section 2; also review the Security log, SSH/GPG keys, deploy keys, apps, webhooks |
| 2 | Cloud providers (AWS, GCP, Azure, Cloudflare, DigitalOcean, Vercel, Netlify, Supabase, Firebase, Render, Railway...) | Revoke access keys and sessions; create new keys; check recent activity and new IAM users/keys |
| 2 | Servers you SSH into | Remove the old public key from `authorized_keys`; rotate server secrets and any passwords stored in `.env` |
| 2 | Databases | New credentials; rotate connection strings; review recent connections |
| 2 | Package registries | Revoke npm, PyPI, RubyGems, crates.io, Docker Hub/GHCR tokens. If you publish packages, **check published versions** for ones you did not release |
| 3 | GitHub Actions secrets, in every repo that has them | New values for each secret that the workflows referenced (use `devguard-mcp actions owner/repo` to list the names) |
| 3 | API keys (payment, email, SMS, analytics, AI services, maps...) | Regenerate in each provider's dashboard |
| 3 | CI/CD and deployment tokens | Regenerate (Vercel, GitHub deploy keys, CI variables) |
| 3 | App signing and certificates (Apple/Android keystores, code-signing, TLS keys) | Revoke and re-issue if they were on the machine |
| 4 | Browser: saved passwords, cookies, autofill, extensions | Treat as stolen: change those passwords, sign out everywhere, remove cards from autofill |
| 4 | Apple ID / Google / Microsoft accounts | New passwords, review devices and sessions |
| 4 | Messaging and collaboration (Slack, Discord, Telegram, Teams, Notion, Linear, Jira) | Sign out all sessions; revoke tokens/bots |
| 4 | VPN, remote desktop (AnyDesk, TeamViewer), RDP/VNC | Change passwords; review connection logs |
| 5 | **Crypto wallets** | If a seed phrase or wallet file was on the machine or in a browser, **move funds to a newly generated wallet** (ideally hardware-backed) immediately. A "new password" does not help |
| 5 | Banking and cards | Watch for unfamiliar activity; ask your bank about card replacement if details were saved in the browser |

Tips

- Rotate **providers' tokens first, then the repo secrets** that hold them.
- Delete the old credential **after** the new one is deployed, but do not leave the old one valid.
- Keep a list of what you rotated and when; it becomes your incident record.
- If a credential protects customer or company data, tell the owner (and your legal/compliance
  contact if applicable): you may have notification duties.

## 7. Clean your repositories and GitHub

Do this from the rebuilt machine, after section 2.

1. **Find everything infected** (all repos, all branches), using your own `gh` login:
   ```bash
   devguard-mcp github YOUR_USERNAME --max-repos 200 --max-branches 50
   devguard-mcp github YOUR_ORG
   ```
2. **Plan and apply the clean-up** in a fresh clone of each affected repo:
   ```bash
   devguard-mcp fix .             # dry run: read every diff
   devguard-mcp fix . --apply     # quarantines originals, then edits
   devguard-mcp scan . --fail-on low
   ```
   Repeat on **every infected branch**. Commit with a normal commit ("security: remove malicious
   payload") and push. Workflows, ambiguous files and `tasks.json` with several tasks are reported
   as *manual*: review them yourself.
3. **Leave the history alone** unless you must. The malicious commits remain in history but are
   harmless once the files are gone; rewriting history on shared repos causes collisions and the
   attacker's tooling itself force-pushes. If a secret was committed, rotating it is the fix.
4. **Block re-infection:** branch protection (required reviews, no force-push) on `main`/`develop`,
   CODEOWNERS covering `.github/workflows/`, secret scanning with push protection, Actions default
   permissions set to **read-only**, workflow runs from forks require approval.
5. **GhostAction check:** run `devguard-mcp workflows .` in each repo, look for unfamiliar entries in
   the *Actions* tab (including *disabled* and *deleted* workflows), and rotate every secret the
   workflows could read.
6. **Tell collaborators.** Anyone with an old clone can push the malware back. Each person should
   delete their old clones, run `devguard-mcp machine` and `devguard-mcp scan`, rotate their
   credentials, and clone fresh. Re-scan the repositories a few days later to catch re-infection.
7. **Check releases and packages:** if you publish artifacts, verify recent versions are yours and
   yank/deprecate any that are not.

## 8. If you cannot reset yet: best-effort containment

Use this only as a **stop-gap** until you can reset. It does not give you a trustworthy machine.

1. Rotate credentials from a clean device (sections 2 and 6) **first**.
2. Disconnect from the network while you work; reconnect only for what you must do.
3. **Do not reopen** any infected project or run any package manager. Close editors that opened it
   and clear them from "recent folders" (VS Code reopens the last folder on start).
4. Stop and quarantine the runner (do not delete evidence you may need):
   - find it: `devguard-mcp machine`
   - stop the `node -e` process it reports (`kill <pid>`; Windows: Task Manager or
     `Stop-Process -Id <pid>`), then **move** `~/.node_modules` somewhere safe and mark it
     non-executable.
5. Inspect persistence the tool checks and a few it cannot see: login items, LaunchAgents/Daemons
   (macOS), Task Scheduler and the `Run` keys (Windows), crontab, systemd user units and autostart
   entries (Linux), shell startup files, SSH `authorized_keys`, browser extensions, installed
   remote-access tools, and unfamiliar user accounts.
6. Neutralise infected projects with `devguard-mcp fix <path> --apply`, then scan again.
7. Remove tokens from shell history and git remotes (`devguard-mcp machine` and `scan` report them):
   `git remote set-url origin <clean-url>`.
8. Install an outbound firewall (LuLu or Little Snitch on macOS, the built-in firewall rules on
   Windows/Linux) and watch for unknown programs connecting out.
9. Re-run `devguard-mcp machine` after every restart for a few days.
10. **Schedule the reset.** A machine you "cleaned" is still a machine you do not fully trust.

## 9. Verify and monitor

After the rebuild and rotation:

- [ ] `devguard-mcp machine`: no findings
- [ ] `devguard-mcp github YOUR_USERNAME`: no findings on any branch
- [ ] `devguard-mcp token`: no `workflow`, `delete_repo` or `admin:*` scopes you do not need
- [ ] GitHub Security log shows no unfamiliar sign-ins or token use after the rotation
- [ ] Every provider in section 6 shows only your own recent activity
- [ ] Collaborators have rebuilt or cleaned their machines
- [ ] Wallets moved; no unexpected transfers

Keep watching for **30 days**: failed or unfamiliar sign-ins, new SSH keys, new Actions
workflows, unexpected commits or force-pushes, surprise cloud bills or API usage, password-reset
emails you did not request.

## 10. Harden so it does not happen again

| Risk | Mitigation |
|------|-----------|
| Running unfamiliar repos (interview "tasks", templates) | Never on your main machine/account. Use a throwaway VM, a Docker devcontainer, or a separate OS user. Scan first with `devguard-mcp scan` |
| Editors executing project content | VS Code **Workspace Trust**: open unknown folders in *Restricted Mode*; disable `task.allowAutomaticTasks`; keep extensions few and from verified publishers |
| Stolen tokens | Fine-grained tokens limited to specific repos and permissions; **no `workflow` scope** unless required; short expiry; never put tokens in clone URLs (`gh auth login` or SSH) |
| Stolen SSH keys | New ed25519 key **with a passphrase**, stored in the OS keychain/agent, or a hardware key (`ed25519-sk`) |
| Account takeover | Passkeys or hardware keys for GitHub, email and cloud; a password manager with unique passwords |
| Malicious workflows | Actions default permissions read-only; pin actions to commit SHAs; require approval for fork workflows; CODEOWNERS on `.github/workflows/`; branch protection |
| Secrets in files | Keep `.env` out of repos; use a secret manager; enable GitHub secret scanning and push protection; store only the secrets a project needs |
| Phoning home | Outbound firewall; DNS filtering |
| Dependency attacks | Lockfiles; install with `npm ci`; review new/obscure packages; pin versions; consider `npm config set ignore-scripts true` for untrusted installs (note: this does **not** stop `node api.js &&` prefixes or config files loaded by tools) |
| Not noticing next time | Run `devguard-mcp machine` and `scan` periodically, or add `devguard-mcp scan . --fail-on high` to CI and pre-commit (see [USAGE.md](USAGE.md)) |

## 11. Special cases and FAQ

**Should I keep the infected machine for evidence?** If this involves an employer, customers, or
a crime report, keep the disk intact and offline, and let the incident-response team image it. Do
not run, open or share the samples. If you only want to understand what happened, the scan output
and `git` history are enough.

**I only opened the folder; I did not run anything.** Opening can still execute code: editor
extensions load `postcss.config.*`/`eslint.config.*`, and `runOn: folderOpen` tasks run when a
workspace is trusted. Treat it as run.

**The machine check says clean, but I ran the project.** The runner may have been deleted, may
not have started yet, or may use persistence this tool does not check. Prefer a reset; if not, use
section 8.

**Do I really need to reset if my antivirus found nothing?** Antivirus detections for this kind of
obfuscated JavaScript are unreliable. A clean scan from any tool is not proof of a clean machine.

**Will changing my GitHub password be enough?** No. Revoke tokens, SSH keys and OAuth apps, and
review the Security log; sessions and tokens survive a password change.

**My repos were infected but I never ran anything.** Another machine or a token did it. Revoke
tokens, check collaborators' machines, review the Security log, and clean the repos (section 7).

**How long was I exposed?** From the first run of the infected project. Commit dates in infected
repositories are unreliable (the attacker rewinds clocks), so use machine logs, file creation
times (for example `~/.node_modules`), and provider audit logs instead.

**What if the infected project belongs to a team or school?** Tell the owner and your instructor
or manager. Their repository is the likely source for the next victim. Do not clean it
unilaterally if you do not own it: report it and share the indicators (never the payload).

**Where do I report this?** GitHub's security team (for infected repos and accounts), the owners of
the repositories involved, and [OpenSourceMalware](https://opensourcemalware.com), sharing
indicators only. See [SECURITY.md](../SECURITY.md#handling-malware-samples) and
[THREAT_INTEL.md](THREAT_INTEL.md).

**Safe-handling reminder.** Never run, import or "just test" a flagged file. Do not paste payloads
into chat tools or issues; describe their structure instead.
