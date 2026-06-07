#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/cli.py

"""CLI for scitex-security — GitHub security-alert utilities.

Subcommands follow the verb-noun convention (general/03_interface_02_cli):

    scitex-security check [REPO]            # Check Dependabot/CodeQL alerts
    scitex-security show-latest             # Print latest saved report
    scitex-security list-python-apis        # Introspect public Python API
    scitex-security mcp list-tools          # Introspect MCP tool surface (none)
"""

from __future__ import annotations

import json as _json
from pathlib import Path

import click

from .github import (
    GitHubSecurityError,
    check_github_alerts,
    format_alerts_report,
    get_latest_alerts_file,
    save_alerts_to_file,
)


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("scitex-security")
    except Exception:  # pragma: no cover
        return "unknown"


def _show_recursive_help(ctx: click.Context) -> None:
    """Print help for the root group plus every subcommand recursively."""
    click.echo(ctx.get_help())
    click.echo()
    group = ctx.command
    if isinstance(group, click.Group):
        for name in sorted(group.list_commands(ctx)):
            cmd = group.get_command(ctx, name)
            if cmd is None or cmd.hidden:
                continue
            sub_ctx = click.Context(cmd, parent=ctx, info_name=name)
            click.echo("=" * 60)
            click.echo(f"Command: {name}")
            click.echo("=" * 60)
            click.echo(sub_ctx.get_help())
            click.echo()
            if isinstance(cmd, click.Group):
                for sub_name in sorted(cmd.list_commands(sub_ctx)):
                    sub_cmd = cmd.get_command(sub_ctx, sub_name)
                    if sub_cmd is None or sub_cmd.hidden:
                        continue
                    sub_sub_ctx = click.Context(
                        sub_cmd, parent=sub_ctx, info_name=sub_name
                    )
                    click.echo("-" * 60)
                    click.echo(f"Command: {name} {sub_name}")
                    click.echo("-" * 60)
                    click.echo(sub_sub_ctx.get_help())
                    click.echo()


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(_version(), "-V", "--version", prog_name="scitex-security")
@click.help_option("-h", "--help")
@click.option("--help-recursive", is_flag=True, help="Show help for all subcommands.")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit structured JSON output (propagates to subcommands that honour it).",
)
@click.pass_context
def main(ctx: click.Context, help_recursive: bool, as_json: bool) -> None:
    """scitex-security — GitHub security-alert utilities (Dependabot, CodeQL, secret scanning).

    \b
    Config is loaded with the SciTeX precedence chain:
      config.yaml -> $SCITEX_SECURITY_CONFIG -> ~/.scitex/security/config.yaml -> defaults
    """
    ctx.ensure_object(dict)
    ctx.obj["as_json"] = as_json
    if help_recursive:
        _show_recursive_help(ctx)
        ctx.exit(0)
    elif ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# --------------------------------------------------------------------------- #
# `scitex-security check` — INTRANSITIVE multi-tool security sweep            #
# (bandit + shellcheck + pip-audit + github). Absorbed from scitex-audit 0.2.0 #
# per ADR-0002 (scitex-dev #142).                                              #
# --------------------------------------------------------------------------- #


@main.command("check")
@click.argument("path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option(
    "--checks",
    multiple=True,
    type=click.Choice(["python", "shell", "deps", "github"]),
    help="Which checks to run (repeat the flag). Defaults to all available.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(),
    default=None,
    help="If given, write JSON report to this path.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
@click.pass_context
def check_cmd(
    ctx: click.Context,
    path: str,
    checks: tuple,
    output_file: "str | None",
    as_json: bool,
) -> None:
    """Run a multi-tool security sweep over PATH.

    Runs bandit (Python), shellcheck (shell), pip-audit (deps), and the
    GitHub-alerts checker. Skips checks whose backing tool isn't
    installed.

    PATH defaults to the current directory.

    \b
    Example:
      $ scitex-security check
      $ scitex-security check .
      $ scitex-security check src/
      $ scitex-security check . --checks python --checks shell
      $ scitex-security check . --output /tmp/audit.json
      $ scitex-security check . --json
    """
    from ._format import format_json, format_text
    from ._runner import audit

    as_json = as_json or bool(ctx.obj.get("as_json"))
    results = audit(
        path=path,
        checks=list(checks) if checks else None,
        output_file=output_file,
    )

    if as_json:
        click.echo(format_json(results))
    else:
        click.echo(format_text(results))

    # Exit 1 if any check found violations, else 0.
    any_findings = any(
        r.get("status") == "findings" for r in results.values() if isinstance(r, dict)
    )
    ctx.exit(1 if any_findings else 0)


# --------------------------------------------------------------------------- #
# `scitex-security github` — noun subgroup for the GH-alerts subset           #
# (replaces the old top-level `check REPO` from 0.1.4; matches noun-verb     #
# convention).                                                                #
# --------------------------------------------------------------------------- #


@main.group(name="github", invoke_without_command=True)
@click.pass_context
def github_group(ctx: click.Context) -> None:
    """GitHub security-alerts commands (Dependabot / CodeQL / secret scanning).

    \b
    Example:
      $ scitex-security github check .
      $ scitex-security github show-latest
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@github_group.command("check")
@click.argument("repo", required=False, default=".")
@click.option(
    "--save",
    is_flag=True,
    help="Save the report to ~/.scitex/security/runtime/<timestamp>.txt.",
)
@click.option(
    "--output-dir",
    default=None,
    help="Output directory for --save (default: ~/.scitex/security/runtime/).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
@click.pass_context
def github_check_cmd(
    ctx: click.Context,
    repo: str,
    save: bool,
    output_dir: "str | None",
    as_json: bool,
) -> None:
    """Check Dependabot / CodeQL / secret-scanning alerts for REPO.

    REPO is 'owner/repo'. Use '.' (default) to auto-detect from the
    current git repo.

    \b
    Example:
      $ scitex-security github check .
      $ scitex-security github check ywatanabe1989/scitex-security
      $ scitex-security github check ywatanabe1989/scitex-security --save
      $ scitex-security github check . --json
    """
    as_json = as_json or bool(ctx.obj.get("as_json"))
    try:
        alerts = check_github_alerts(None if repo == "." else repo)

        total = sum(
            len([a for a in alerts[key] if a.get("state") == "open"]) for key in alerts
        )

        saved_path = None
        if save:
            out_path = Path(output_dir) if output_dir else None
            saved_path = save_alerts_to_file(alerts, out_path)

        if as_json:
            payload = {
                "repo": repo,
                "open_alerts": total,
                "alerts": alerts,
                "saved_path": str(saved_path) if saved_path else None,
            }
            click.echo(_json.dumps(payload, indent=2, default=str))
        else:
            if saved_path:
                click.echo(f"Report saved to: {saved_path}")
                click.echo(
                    f"Latest symlink: {saved_path.parent / 'security-latest.txt'}"
                )
            click.echo(format_alerts_report(alerts))
            if total > 0:
                click.echo(f"Found {total} open security alert(s)", err=True)

        ctx.exit(1 if total > 0 else 0)

    except GitHubSecurityError as e:
        if as_json:
            click.echo(_json.dumps({"error": str(e)}, indent=2), err=True)
        else:
            click.echo(f"ERROR: {e}", err=True)
        ctx.exit(2)


@github_group.command("show-latest")
@click.option(
    "--security-dir",
    default=None,
    help="Directory holding saved reports (default: ~/.scitex/security/runtime/).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
@click.pass_context
def github_show_latest_cmd(
    ctx: click.Context, security_dir: "str | None", as_json: bool
) -> None:
    """Print the most recent saved GitHub-alerts report.

    \b
    Example:
      $ scitex-security github show-latest
      $ scitex-security github show-latest --security-dir ~/.scitex/security/runtime
      $ scitex-security github show-latest --json
    """
    as_json = as_json or bool(ctx.obj.get("as_json"))
    dir_path = Path(security_dir) if security_dir else None

    try:
        latest_file = get_latest_alerts_file(dir_path)
    except Exception as e:
        if as_json:
            click.echo(_json.dumps({"error": str(e)}, indent=2), err=True)
        else:
            click.echo(f"ERROR: {e}", err=True)
        ctx.exit(2)
        return

    if not latest_file:
        if as_json:
            click.echo(_json.dumps({"latest": None}, indent=2))
        else:
            click.echo("No security alerts files found", err=True)
        ctx.exit(1)
        return

    try:
        content = latest_file.read_text()
    except Exception as e:
        if as_json:
            click.echo(_json.dumps({"error": str(e)}, indent=2), err=True)
        else:
            click.echo(f"ERROR: {e}", err=True)
        ctx.exit(2)
        return

    if as_json:
        click.echo(
            _json.dumps({"latest": str(latest_file), "content": content}, indent=2)
        )
    else:
        click.echo(content)


# -- Introspection ----------------------------------------------------------


@main.command("list-python-apis")
@click.option("-v", "--verbose", count=True, help="-v names, -vv +sigs, -vvv +docs")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def list_python_apis(ctx: click.Context, verbose: int, as_json: bool) -> None:
    """List public Python APIs in scitex-security.

    \b
    Example:
      $ scitex-security list-python-apis
      $ scitex-security list-python-apis -vv
      $ scitex-security list-python-apis --json
    """
    import inspect

    import scitex_security

    as_json = as_json or bool(ctx.obj.get("as_json"))

    names = sorted(getattr(scitex_security, "__all__", []))
    apis = []
    for name in names:
        obj = getattr(scitex_security, name, None)
        if obj is None:
            continue
        entry = {"name": name, "type": type(obj).__name__}
        if callable(obj):
            try:
                entry["signature"] = str(inspect.signature(obj))
            except (TypeError, ValueError):
                pass
        doc = inspect.getdoc(obj) or ""
        if doc:
            entry["doc"] = doc.strip().split("\n")[0]
        apis.append(entry)

    if as_json:
        click.echo(_json.dumps({"module": "scitex_security", "apis": apis}, indent=2))
        return

    click.secho("scitex_security Python APIs", fg="cyan", bold=True)
    for api in apis:
        sig = api.get("signature", "")
        click.echo(f"  {click.style(api['name'], fg='green')}{sig}")
        if verbose >= 2 and api.get("doc"):
            click.echo(f"    {api['doc']}")


# -- MCP --------------------------------------------------------------------


@main.group(invoke_without_command=True)
@click.pass_context
def mcp(ctx: click.Context) -> None:
    """MCP (Model Context Protocol) commands. scitex-security ships no MCP server."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@mcp.command("list-tools")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def mcp_list_tools(ctx: click.Context, as_json: bool) -> None:
    """List MCP tools exposed by scitex-security (currently none).

    \b
    Example:
      $ scitex-security mcp list-tools
      $ scitex-security mcp list-tools --json
    """
    as_json = as_json or bool(ctx.obj.get("as_json"))
    if as_json:
        click.echo(_json.dumps({"total": 0, "tools": []}, indent=2))
        return
    click.secho("scitex-security MCP: 0 tools (no MCP server)", fg="cyan", bold=True)


# Wire the skills group (audit-cli §1a — packages with _skills/ MUST
# expose `<cli> skills {list,get,install}`).
from ._skills import skills_group as _skills_group

main.add_command(_skills_group, name="skills")


# Wire canonical install-shell-completion + print-shell-completion (§1a).
try:
    from scitex_dev._cli._completion import attach_shell_completion

    attach_shell_completion(main, prog_name="scitex-security")
except ImportError:
    pass


if __name__ == "__main__":
    main()


# audit §4 — inject version into root --help
try:
    from importlib.metadata import version as _v

    main.help = (
        f"scitex-security (v{_v('scitex-security')}) — " + (main.help or "").lstrip()
    )
except Exception:
    pass
