---
description: |
  [TOPIC] Look-alike domain watch
  [DETAILS] Typosquat / IDN-homograph / TLD-swap / affix domains of a domain you own: DNS (A/AAAA/MX/NS), Certificate Transparency (crt.sh), RDAP registration date; stateful, alerts only on new registrations, new MX, new certificates.
tags: [scitex-security-domain-watch]
---

# Look-alike domain watch

Someone who registers `example-ai.com`, `exampIe.ai` or `ехаmple.ai`
(Cyrillic letters) can mail as your organisation. This watch finds such
names and tells you when one appears, gains mail exchangers, or gets a TLS
certificate.

## CLI

```bash
scitex-security domains list-candidates example.ai              # what would be checked (offline)
scitex-security domains list-candidates example.ai --kind homoglyph --json
scitex-security domains watch example.ai example.net       # probe + table; exit 1 if new events
scitex-security domains watch example.ai --notify          # mail new events (ops profile)
scitex-security domains watch example.ai --dry-run-notify  # validate the mail, send nothing
scitex-security domains watch example.ai --no-ct --no-rdap --json
```

## Python

```python
from scitex_security.domains import generate_lookalike_domains, watch_domains

candidates = generate_lookalike_domains("example.ai")          # [Candidate(name, ascii, kind, detail)]
result = watch_domains(["example.ai"], notify=False)
for report in result["reports"]:
    for hit in report.hits:                                     # registered look-alikes
        print(hit["risk"], hit["name"], hit["mx"], hit["created"])
    for event in report.events:                                 # new since last run
        print(event.kind, event.name, event.detail)
```

DNS and HTTP are injected (`query=`, `fetch=`), so tests pass real fakes.

## What is generated

| kind | example for `example.ai` | TLDs |
|---|---|---|
| omission / repetition / transposition / adjacent-key | `exmple.ai`, `exaample.ai`, `exmaple.ai`, `exsmple.ai` | own + `.com` |
| homoglyph | `ехample.ai` (Cyrillic х, punycode `xn--...`), `exarnple.ai` (rn for m), all-Cyrillic spelling | own + `.com` |
| tld-swap | `example.com/.io/.co/.app/.dev/.net/.org/.jp/.co.jp` | all |
| hyphenation | `exam-ple.com` | all |
| affix | `getexample.ai`, `example-app.com`, `example-ai.com`, `exampleai.com` | all |
| ct | any non-owned name starting with the label that appears in CT logs | n/a |

Word lists and TLDs are arguments (`tlds=`, `prefixes=`, `suffixes=`).

## State and events

One JSON file per watched domain in `$SCITEX_SECURITY_DIR/domains/` (else
`$SCITEX_DIR/security/domains/`, default `~/.scitex/security/domains/`).
The first run is a **baseline**: it records and reports but raises no event.
After that an event is raised only for:

- `new-registration`: a look-alike exists that did not before;
- `new-mx`: a known look-alike gained MX records (it can send/receive mail);
- `new-cert`: a new unexpired certificate names a look-alike.

Risk per hit: **high** = registered in the last 90 days (RDAP), or a
brand-intact look-alike with MX records (homoglyph, TLD swap, affix,
hyphenation; or a CT-found name whose label is the brand or the brand plus a
hyphenated word); **medium** = any other look-alike with MX, or a
brand-intact name that resolves; **low** = the rest (parked names; typos and
longer words that are other real names, which a short brand has many of).
Certificate dates do not raise risk (ACME certificates renew every 60-90
days on old domains too); a new certificate is an event instead.

CT is queried two ways: the `label%` prefix (finds names nobody generated,
e.g. `example-pay.xyz`; crt.sh silently returns nothing for a leading
`%label%` wildcard, so that form is not used), and the exact name of every
registered look-alike (cheap; covers punycode names).

## Alerts

`--notify` sends ONE `notice` (scitex-notification) per run for all pending
events, as profile `ops` (`SCITEX_NOTIFICATION_PROFILE_OPS_*`; the password
may be `..._PASSWORD_GPG`). At most one mail per host per 6 h; events found
in between stay pending in the state files and are never lost: they are
cleared only after the SMTP server accepts the mail.
Install: `pip install 'scitex-security[notify]'`.

## Scheduling

`examples/systemd/scitex-security-domains.{service,timer}` run the watch
daily as a user unit; per-host arguments and the profile live in
`~/.scitex/security/domains.env`.

## Limits

- Looks only at names the generators produce plus what crt.sh returns for
  the label; a look-alike with a different word and no certificate is not
  seen.
- crt.sh is a shared free service: non-empty answers are cached 6 h,
  queries are spaced 3 s, and a failure is reported in `errors`, not raised.
- RDAP dates come from each registry directly (IANA bootstrap), once per
  name (kept in state); registries without RDAP (e.g. `.jp`) leave
  `created` empty.
