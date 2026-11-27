#!/usr/bin/env python3
# File: src/scitex_security/_cli_domains.py

"""``scitex-security domains {candidates,watch}`` — look-alike domain watch."""

from __future__ import annotations

import json as _json

import click


@click.group(name="domains", invoke_without_command=True)
@click.pass_context
def domains_group(ctx: click.Context) -> None:
    """Look-alike (typosquat / homograph) domain watch.

    \b
    Example:
      $ scitex-security domains candidates example.org
      $ scitex-security domains watch example.org
      $ scitex-security domains watch example.org example.net --notify
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@domains_group.command("candidates")
@click.argument("domain")
@click.option(
    "--kind",
    "kinds",
    multiple=True,
    help="Generator(s): omission, repetition, transposition, adjacent-key, "
    "homoglyph, hyphenation, affix, tld-swap. Default: all.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def candidates_cmd(ctx, domain: str, kinds: tuple, as_json: bool) -> None:
    """List look-alike names generated for DOMAIN (no network).

    \b
    Example:
      $ scitex-security domains candidates example.org
      $ scitex-security domains candidates example.org --kind homoglyph
      $ scitex-security domains candidates example.org --json
    """
    from .domains import generate_lookalike_domains

    as_json = as_json or bool((ctx.obj or {}).get("as_json"))
    found = generate_lookalike_domains(domain, kinds=kinds or None)
    if as_json:
        rows = [
            {"name": c.name, "ascii": c.ascii, "kind": c.kind, "detail": c.detail}
            for c in found
        ]
        click.echo(_json.dumps({"domain": domain, "candidates": rows}, indent=2))
        return
    for c in found:
        shown = c.name if not c.is_idn else f"{c.name} ({c.ascii})"
        click.echo(f"{c.kind:14} {shown:40} {c.detail}")
    click.echo(f"{len(found)} candidates", err=True)


def _table(report) -> str:
    lines = [
        f"## {report.domain}: {len(report.hits)} registered look-alike(s) of "
        f"{report.candidates} checked" + ("  [baseline]" if report.baseline else "")
    ]
    if report.hits:
        lines.append(
            f"{'risk':6} {'name':34} {'kind':13} {'A':16} {'MX':28} "
            f"{'created':10} certs"
        )
    for h in report.hits:
        name = h["name"] if h["name"] == h["ascii"] else f"{h['name']} ({h['ascii']})"
        lines.append(
            f"{h['risk']:6} {name[:34]:34} {str(h['kind'])[:13]:13} "
            f"{(h['a'] or ['-'])[0][:16]:16} {', '.join(h['mx'])[:28] or '-':28} "
            f"{h['created'] or '-':10} {h['certs']}"
        )
    for e in report.events:
        lines.append(f"EVENT [{e.risk}] {e.kind}: {e.name} {e.detail}")
    for err in report.errors[:10]:
        lines.append(f"error: {err}")
    if len(report.errors) > 10:
        lines.append(f"... {len(report.errors) - 10} more errors (--json)")
    return "\n".join(lines)


@domains_group.command("watch")
@click.argument("domains", nargs=-1, required=True)
@click.option("--owned", multiple=True, help="Another domain you own (never reported).")
@click.option(
    "--state-dir",
    type=click.Path(file_okay=False),
    default=None,
    help="State directory (default: $SCITEX_DIR/security/domains).",
)
@click.option(
    "--ct/--no-ct",
    default=True,
    show_default=True,
    help="Query Certificate Transparency (crt.sh).",
)
@click.option(
    "--rdap/--no-rdap",
    default=True,
    show_default=True,
    help="Look up registration dates (RDAP).",
)
@click.option(
    "--notify/--no-notify",
    default=False,
    show_default=True,
    help="Mail new events as a scitex-notification notice.",
)
@click.option(
    "--profile",
    default="ops",
    show_default=True,
    help="scitex-notification sender profile.",
)
@click.option(
    "--dry-run-notify",
    is_flag=True,
    help="Validate and rate-check the notice without sending.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def watch_cmd(ctx, domains, owned, state_dir, ct, rdap, notify, profile,
              dry_run_notify, as_json) -> None:  # fmt: skip
    """Probe look-alikes of DOMAINS; report hits, alert only on new ones.

    New = a newly registered look-alike, new MX records on one, or a new
    certificate for one. The first run per domain records a baseline and
    raises no events. Exit 0 when nothing is new, 1 when events are new.

    \b
    Example:
      $ scitex-security domains watch example.org
      $ scitex-security domains watch example.org example.net --notify
      $ scitex-security domains watch example.org --no-ct --json
    """
    from .domains import watch_domains

    as_json = as_json or bool((ctx.obj or {}).get("as_json"))
    result = watch_domains(
        list(domains),
        owned=owned,
        state_dir=state_dir,
        ct=ct,
        rdap=rdap,
        notify=notify or dry_run_notify,
        profile=profile,
        dry_run_notify=dry_run_notify,
    )
    reports = result["reports"]
    if as_json:
        payload = {
            "reports": [r.to_dict() for r in reports],
            "pending_events": result["pending"],
            "notify": result["notify"],
        }
        click.echo(_json.dumps(payload, indent=2, default=str))
    else:
        click.echo("\n\n".join(_table(r) for r in reports))
        if result["notify"]:
            click.echo(f"notify: {result['notify'].get('status')}")
    ctx.exit(1 if any(r.events for r in reports) else 0)


# EOF
