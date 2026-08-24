from __future__ import annotations

import json
import os
from pathlib import Path

import typer
from rich.console import Console

from .. import __version__
from ..core.errors import EvidenceVeilError
from ..discovery import discover
from ..metadata import AUTHOR_NAME, GITHUB_HANDLE, LICENSE_ID, REPOSITORY, WEBSITE
from ..packaging.bundle import sanitize
from ..policies.engine import builtin_policy_dir, load_policy
from ..restore import restore as restore_data
from ..risk.audit import audit_path
from ..utility.validate import validate_contract
from ..verify import verify_bundle

app = typer.Typer(
    help="EvidenceVeil — Share incident data without exposing the incident.",
    epilog=f"Created and maintained by {AUTHOR_NAME} · {WEBSITE} · GitHub: {GITHUB_HANDLE}",
    no_args_is_help=True,
)
policies_app = typer.Typer(help="Inspect and validate sanitization policies.")
formats_app = typer.Typer(help="List supported formats.")
plugins_app = typer.Typer(help="List trusted-code plugin interfaces.")
utility_app = typer.Typer(help="Validate analytical utility contracts.")
app.add_typer(policies_app, name="policies")
app.add_typer(formats_app, name="formats")
app.add_typer(plugins_app, name="plugins")
app.add_typer(utility_app, name="utility")
console = Console()


def _emit(data: object, json_mode: bool = False) -> None:
    if json_mode:
        typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        console.print(data)


def _passphrase() -> str:
    p = os.getenv("EVIDENCEVEIL_VAULT_PASSPHRASE")
    if p:
        return p
    prompt_value: str = typer.prompt("Vault passphrase", hide_input=True, confirmation_prompt=False)
    return prompt_value


@app.command()
def version() -> None:
    """Print the installed EvidenceVeil version."""
    console.print(f"EvidenceVeil {__version__}")
    console.print(f"Created and maintained by {AUTHOR_NAME}")
    console.print(f"{WEBSITE} · GitHub: {GITHUB_HANDLE}")


@app.command()
def about(json_output: bool = typer.Option(False, "--json")) -> None:
    """Show EvidenceVeil project identity and maintainer attribution."""
    data = {
        "product": "EvidenceVeil",
        "version": __version__,
        "tagline": "Share incident data without exposing the incident.",
        "creator": AUTHOR_NAME,
        "maintainer": AUTHOR_NAME,
        "website": WEBSITE,
        "github": GITHUB_HANDLE,
        "repository": REPOSITORY,
        "license": LICENSE_ID,
    }
    _emit(data, json_output)


@app.command()
def doctor(json_output: bool = typer.Option(False, "--json")) -> None:
    """Check local runtime requirements without network access."""
    import platform
    import sys

    data = {
        "product": "EvidenceVeil",
        "version": __version__,
        "author": AUTHOR_NAME,
        "maintainer": AUTHOR_NAME,
        "website": WEBSITE,
        "repository": REPOSITORY,
        "license": LICENSE_ID,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "network_required": False,
        "python_supported": sys.version_info >= (3, 11),
    }
    _emit(data, json_output)
    if not data["python_supported"]:
        raise typer.Exit(2)


@app.command()
def init(path: Path = typer.Argument(Path("evidenceveil-workspace"))) -> None:
    """Create an empty local EvidenceVeil workspace."""
    for name in ("input", "output", "vaults"):
        (path / name).mkdir(parents=True, exist_ok=True)
    console.print(f"Created workspace: {path}")


def discover_cmd(
    input: Path = typer.Argument(..., exists=True),
    recursive: bool = True,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Discover formats and sensitive semantic categories without displaying raw values."""
    data = discover(input, recursive).model_dump(mode="json")
    _emit(data, json_output)


@app.command(name="discover")
def discover_alias(
    input: Path = typer.Argument(..., exists=True),
    recursive: bool = True,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    discover_cmd(input, recursive, json_output)


@app.command()
def plan(
    input: Path = typer.Argument(..., exists=True),
    policy: str = typer.Option(..., "--policy"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Resolve a policy and show expected rule actions without changing evidence."""
    pol = load_policy(policy)
    inv = discover(input)
    data = {
        "policy": pol.id,
        "release_model": pol.release_model,
        "rules": [
            {
                "id": r.id,
                "priority": r.priority,
                "action": r.action.type,
                "semantic_types": r.match.semantic_types,
            }
            for r in sorted(pol.rules, key=lambda r: r.priority, reverse=True)
        ],
        "input": {
            "files": len(inv.files),
            "semantic_counts": inv.semantic_counts,
            "potential_secrets": inv.potential_secrets,
        },
    }
    _emit(data, json_output)


def sanitize_cmd(
    input: Path = typer.Argument(..., exists=True),
    policy: str = typer.Option(..., "--policy"),
    output: Path = typer.Option(..., "--output"),
    new_key: bool = typer.Option(False, "--new-key"),
    key_file: Path | None = typer.Option(None, "--key-file"),
    vault: Path | None = typer.Option(None, "--vault"),
    tlp: str | None = typer.Option(None, "--tlp"),
    report: bool = typer.Option(False, "--report"),
    reproducible: bool = typer.Option(False, "--reproducible"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Sanitize evidence into a new shareable bundle; never modifies the input in place."""
    if new_key and key_file:
        raise typer.BadParameter("Use either --new-key or --key-file, not both.")
    if dry_run:
        return plan(input, policy, json_output)
    passphrase = _passphrase() if vault else None
    result = sanitize(
        input,
        policy,
        output,
        key_file=key_file,
        vault=vault,
        passphrase=passphrase,
        report=report,
        reproducible=reproducible,
        tlp=tlp,
    )
    _emit(result, json_output)
    if fail_on_risk and result.get("risk_status") == "blocked":
        raise typer.Exit(4)


@app.command(name="sanitize")
def sanitize_alias(
    input: Path = typer.Argument(..., exists=True),
    policy: str = typer.Option(..., "--policy"),
    output: Path = typer.Option(..., "--output"),
    new_key: bool = typer.Option(False, "--new-key"),
    key_file: Path | None = typer.Option(None, "--key-file"),
    vault: Path | None = typer.Option(None, "--vault"),
    tlp: str | None = typer.Option(None, "--tlp"),
    report: bool = typer.Option(False, "--report"),
    reproducible: bool = typer.Option(False, "--reproducible"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    sanitize_cmd(
        input,
        policy,
        output,
        new_key,
        key_file,
        vault,
        tlp,
        report,
        reproducible,
        dry_run,
        fail_on_risk,
        json_output,
    )


@app.command()
def audit(
    input: Path = typer.Argument(..., exists=True),
    quasi_field: list[str] = typer.Option([], "--quasi-field"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Run post-transformation residual disclosure-risk analysis."""
    data = audit_path(input)
    if quasi_field:
        data["quasi_identifier_fields"] = quasi_field
        data["k_anonymity"] = (
            "not computed for heterogeneous file sets in v1; use structured utility/risk review"
        )
    _emit(data, json_output)


@app.command()
def verify(
    bundle: Path = typer.Argument(..., exists=True),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Verify bundle checksums."""
    _emit(verify_bundle(bundle), json_output)


@app.command()
def restore(
    input: Path = typer.Argument(..., exists=True),
    vault: Path = typer.Option(..., "--vault", exists=True),
    output: Path = typer.Option(..., "--output"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Restore reversible mappings using an authenticated vault."""
    _emit(restore_data(input, vault, output, _passphrase()), json_output)


@app.command()
def diff(
    original: Path = typer.Argument(..., exists=True),
    sanitized: Path = typer.Argument(..., exists=True),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Compare discovery-level structure without displaying original sensitive values."""
    a, b = discover(original), discover(sanitized)
    data = {
        "original_files": len(a.files),
        "sanitized_files": len(b.files),
        "original_semantic_counts": a.semantic_counts,
        "sanitized_semantic_counts": b.semantic_counts,
    }
    _emit(data, json_output)


@policies_app.command("list")
def policies_list() -> None:
    for p in sorted(builtin_policy_dir().glob("*.yaml")):
        console.print(p.stem)


@policies_app.command("show")
def policies_show(policy: str) -> None:
    pol = load_policy(policy)
    console.print_json(data=pol.model_dump(mode="json"))


@policies_app.command("validate")
def policies_validate(path: Path) -> None:
    paths = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    for p in paths:
        load_policy(p)
        console.print(f"[green]OK[/green] {p}")


@policies_app.command("scaffold")
def policies_scaffold(name: str) -> None:
    p = Path(f"{name}.yaml")
    if p.exists():
        raise typer.BadParameter("File already exists.")
    p.write_text(
        f'policy_version: "1.0"\nid: {name}\ntitle: {name}\nrelease_model: known-recipient\ndefault_action: review\nkey_scope: per_run\nrules: []\n',
        encoding="utf-8",
    )
    console.print(f"Created {p}")


@formats_app.command("list")
def formats_list() -> None:
    console.print(
        "text, syslog, CEF, LEEF, JSON, JSONL/NDJSON, CSV, TSV, gzip; "
        "EVTX/Parquet are recognized but unsupported for sanitization in v1.0"
    )


@plugins_app.command("list")
def plugins_list() -> None:
    console.print(
        "Built-in example: evidenceveil.plugins.example.ExampleTicketDetector (plugins are trusted code)"
    )


@utility_app.command("validate")
def utility_validate(
    original: Path,
    sanitized: Path,
    contract: Path = typer.Option(..., "--contract"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    _emit(validate_contract(original, sanitized, contract), json_output)


def main() -> None:
    try:
        app()
    except EvidenceVeilError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


if __name__ == "__main__":
    main()
