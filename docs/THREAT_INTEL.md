# Threat intelligence

What this project knows about the two campaigns, where it comes from, and how much to trust it.
Indicators are strings only; this repository never contains payloads.

> Reporting on both campaigns is moving quickly and sources disagree on dates and scale. Treat the
> numbers below as approximate and check the primary sources. Last reviewed: **2026-10-26**
> (matches `data/iocs.json` `version`).

## PolinRider

**Summary.** A campaign attributed by its researchers to DPRK-linked actors (overlapping with
"Contagious Interview" / BeaverTail tradecraft) that implants obfuscated JavaScript into public
and private GitHub repositories and spreads by rewriting commits.

**Delivery and execution** (as reported, and as observed in a real infection):

| Vector | Notes |
|--------|-------|
| Payload appended to config files | `postcss.config.mjs` (most common), `tailwind.config.js`, `eslint.config.*`, `next.config.*`, `vite.config.*`. Hidden after a long whitespace run on the last line, so editors show a normal file. Runs whenever the tool or an editor extension loads the config. |
| `api.js` dropper | Large obfuscated file; `package.json` scripts become `node api.js && next dev`. |
| Fake font | A `.ttf` that is JavaScript, run by an auto-run `.vscode/tasks.json` task (`runOn: folderOpen`) with `node`. |
| Take-home projects / packages | Fake interview projects and look-alike npm packages (Tailwind/PostCSS themed) were reported; the original infection route is unknown in public reporting. |

**Second stage.** The loader decrypts (XOR) and `eval`s code fetched at runtime, starts a detached
`node -e` process, and, in the variant observed here, keeps a runner under `~/.node_modules`
(`.npm-ws-runner.js`, `.npm-ws.json`, `.npm-ws.pid`) that downloads further code from an HTTP
server. Public reporting describes a BeaverTail-style stealer targeting credentials and crypto
wallets. **This project cannot see the second stage, so it cannot say what a given machine lost.**

**Propagation and anti-forensics.** A helper (`temp_auto_push.bat` in reports) reads the latest
commit, rewinds the system clock to its timestamp, amends the commit to add the payload and
force-pushes, so the change looks like part of the original work. The most distinctive trace we
observed is on the *committer* fields: same instant as the author time but written in a different
timezone (rules `DG-HS-001`, `DG-HS-002`). Because the clock is controlled by the attacker,
**commit dates are not evidence of when an infection happened.**

**Re-infection is real.** In one observed case a cleaned machine was re-infected within the hour:
the editor restarted, re-opened the still-infected project, and an extension that loads
`postcss.config.*` executed the payload. Clean the *project* before reopening it, and rebuild the
machine rather than trusting a manual cleanup.

**Sources**
- OpenSourceMalware, PolinRider dossier: <https://github.com/OpenSourceMalware/PolinRider>
- OpenSourceMalware, campaign write-up:
  <https://opensourcemalware.com/blog/polinrider-dprk-compromised-hundreds-of-github-repos>
- OpenSourceMalware, spread to Go/Packagist/npm/PyPI:
  <https://opensourcemalware.com/blog/polinrider-jumps-the-fence>
- Wiz incident page:
  <https://threats.wiz.io/all-incidents/polinrider-campaign-dprk-linked-supply-chain-attack-infects-github-repositories>
- Hands-on analysis of an infected developer machine (Oct 2026), the source of the `api.js`,
  `.npm-ws*`, HTTP stage and committer-timezone observations.

**What differs between reports and this tool's samples.** Public reports describe loaders that
fetch from blockchain APIs and Vercel-hosted endpoints; the sample analysed here used a plain HTTP
server and an `api.js` dropper. Expect variants; prefer structural rules over string markers.

## GhostAction

**Summary.** A GitHub Actions secret-theft campaign. Using stolen credentials, the attacker pushes
a workflow under the victim's own identity that reads the repository's secrets and posts them to an
attacker-controlled server. Two waves are reported: September 2025 and a larger one in
August-October 2026.

**Behaviour** (as reported):

- Workflow files named `github_actions_security.yml` ("Github Actions Security"),
  `security-check.yml`, `security-audit.yml`; commit messages such as "Add Github Actions Security
  workflow".
- Triggers `push` and `workflow_dispatch`; a job `send-secrets` on `ubuntu-latest`; a step
  "Prepare Cache Busting".
- The workflow hard-codes the secret names it found in the repo's *other* workflows
  (`${{ secrets.VPS_SSH_KEY }}`) and sends them with `curl -s -X POST -d ...` to plain-HTTP hosts
  (for example `193.32.204.199`; older infrastructure is listed in `data/iocs.json`).
- The October 2026 variant also checks out full history, runs `git log -p --all`, greps for cloud
  and AI keys and token formats, and posts the matches.
- Targeted secrets: SSH/deployment keys, cloud credentials (Azure, AWS, GCP/Firebase), container
  registry and package-registry tokens (Docker, npm, PyPI), database and FTP credentials, GitHub
  tokens, chat-service tokens.

**Entry point.** Reports point to previously stolen credentials: personal access tokens and
credentials from infostealer logs, sometimes unrotated secrets from earlier incidents. That makes
the two campaigns *plausibly* chained (an infostealer on a developer machine yields a token with
the `workflow` scope that GhostAction then abuses). This project does **not** claim that link for
any specific case.

**Important for responders.** Rotating the leaked secrets is not enough if the GitHub credential
that pushed the workflow is still valid: revoke it first, otherwise the workflow can be
re-injected.

**Sources**
- GitGuardian: <https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/>
- StepSecurity:
  <https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows>
- CSO Online:
  <https://www.csoonline.com/article/4052826/ghostaction-campaign-steals-3325-secrets-in-github-supply-chain-attack.html>
- The Hacker News (October 2026 wave):
  <https://thehackernews.com/2026/10/credential-stealing-github-actions.html>
- Aviatrix: <https://aviatrix.ai/threat-research-center/ghostaction-github-actions-credential-theft-2026/>

**Disagreement between sources.** Scale for the 2026 wave ranges from hundreds of repositories to
about 30,000, and the dates differ between vendors. We use the *behavioural* indicators, which
agree across sources, and avoid quoting totals as fact.

## Indicator policy

- Indicators live in `src/devguard_mcp/data/iocs.json`; bump `version` (a date) with every change.
- Every new indicator needs a public source or a documented first-hand observation in the pull
  request, and a note of its confidence.
- Prefer hosts/file names/strings over hashes of payloads; never commit payloads.
- Expire or downgrade indicators that become common false positives (see the weak-marker tier).
- Legitimate services (for example public blockchain APIs) are not listed, because they would
  flag benign crypto projects.
