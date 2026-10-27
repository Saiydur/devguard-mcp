# Security policy

## Reporting a vulnerability in devguard-mcp

Please **do not open a public issue** for security problems. Report privately through GitHub's
"Report a vulnerability" button (Security tab -> Advisories) on this repository. If that is
unavailable, contact the maintainers listed in the repository profile.

Include: the version (`devguard-mcp --version`), your OS and Python version, steps to reproduce,
and the impact. We aim to acknowledge reports within 7 days and to ship a fix or mitigation for
confirmed high-severity issues within 30 days. Please allow coordinated disclosure.

### In scope

- Code execution, file write/delete, or path escape triggered by *scanning* untrusted input
  (files, git repositories, GitHub content, process listings).
- Any way for scanned content to make the MCP server perform a write, a delete or a network call
  it should not (the server is meant to be read-only).
- Leaking secrets in output (tokens, secret values) or echoing attacker-controlled payload text
  beyond the documented truncation.
- Regex denial of service on attacker-sized input.
- Bypass of `DEVGUARD_ALLOWED_ROOTS`.
- Weaknesses in the cleanup quarantine (`fix --apply`) that could overwrite unintended files.
- Supply-chain issues in this repository's build, release or CI configuration.

### Out of scope

- A malware variant that evades detection. That is a *detection gap*, not a vulnerability: open a
  normal issue or pull request with a **sanitised** indicator (see below).
- Findings about the campaigns themselves; report those to GitHub and the research teams listed in
  [docs/THREAT_INTEL.md](docs/THREAT_INTEL.md).

## Handling malware samples

This project analyses real malware. To keep contributors and users safe:

- **Never attach, paste or commit live payloads**, working loaders, or code that decrypts or
  executes them. Describe indicators instead: marker strings, file names, hosts, structure
  (for example "a 12 KB single line after 200 spaces"), and sizes.
- If you must share a sample with maintainers, say so privately first; do not upload it to issues.
- Test fixtures must be synthetic: filler text plus the *public* indicator strings.
- Analyse samples only in an isolated VM or container. Never run them.

## Supported versions

Only the latest released version receives security fixes while the project is in alpha (0.x).

## Safe-use reminders

- Run as an unprivileged user.
- Pin the version you install and verify it came from this repository.
- A clean scan is not proof of safety; see the README's Limitations.
