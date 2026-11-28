---
description: |
  [TOPIC] Credential rotation
  [DETAILS] Operator-run `scitex-security rotate-credential PAYLOAD VARS [--dry-run]` — hidden-prompt value intake, isolated python -I worker, exact env-diff proof, same-recipient re-encryption, installed manifest + exactly one entry, typed `install` confirmation, fleet install (hosts without trust dir skipped with reason), dotfiles PR. All fleet facts come from config.
tags: [scitex-security-credential-rotation]
---

# Credential rotation (operator-run)

Replaces variables inside a signed, encrypted shell payload of the
signed-manifest design (root-owned verifier, `/etc/scitex-secrets` trust
dir, controller-only issuer key). Run it in the operator's own terminal
on the controller. Agents never run it: it needs the operator to type the
new value.

```bash
scitex-security rotate-credential bash-config-<24hex>.gpg GH_TOKEN --dry-run
scitex-security rotate-credential bash-config-<24hex>.gpg GH_TOKEN,GITHUB_TOKEN
```

## Guarantees

- The value is read once from a hidden prompt on `/dev/tty`. It is never
  taken from argv, the environment, a file or a pipe, and is never logged.
  Without a terminal the command aborts.
- The click command only resolves config. The work runs in
  `<python> -I _rotate/_entry.py`, which imports the standard library
  and the stdlib-only worker modules of `scitex_security/_rotate/` only. The launcher renders the worker's
  JSON events (names, statuses, hashes).
- Value shape checked (`github-pat` = `github_pat_` + 82 word chars;
  `generic`). A GitHub token must answer `GET /user` with 200.
- Only the named variables may change. The payload is loaded in a clean
  bash before and after the replacement, and the load status, all other
  exported variables and the function hash must be identical.
- The payload is re-encrypted to the same recipient key set, and a
  round-trip decrypt must match.
- Candidate manifest = installed manifest + exactly one entry. Python
  checks this before signing, and each host's installer checks it again
  before installing.
- Nothing is signed until the operator types `install`. `--dry-run` stops
  before signing and removes its temporary directory.
- Every configured host is probed first. A host without the trust dir or
  verifier is reported `SKIPPED (...)`. `skipped_hosts` are reported with
  their configured reason. If any host fails, no PR is opened.

## Config (`rotate_credential:`; required keys have no default)

```yaml
rotate_credential:
  controller: ctl-host                 # required; must be in hosts
  hosts: [ctl-host, worker-01]         # required
  skipped_hosts: {hpc: no noninteractive administrator installation}
  issuer_fingerprint: <40 hex>         # required (primary key, VALIDSIG pin)
  expected_recipient_count: 8          # optional extra check
  github:
    dotfiles_repo: owner/.dotfiles     # required: PR target
    base_branch: develop
    pat_variables: [GH_TOKEN, GITHUB_TOKEN]
    pat_variable_prefixes: [SCITEX_GH_TOKEN]
    pr_token_variable: SCITEX_GH_TOKEN_OWNER   # new value used if it is rotated
  # paths (defaults shown)
  trust_dir: /etc/scitex-secrets
  verifier: /opt/scitex-secrets/verified_payload.py
  signing_home: /var/lib/scitex-secrets-signing
  python: /usr/bin/python3
  payload_dir: ~/.pw
  dotfiles_dir: ~/.dotfiles
```

Exit status: 0 ok, 1 some host failed, 2 aborted or config error, 130
interrupted.
