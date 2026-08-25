from pathlib import Path

from typer.testing import CliRunner

from evidenceveil.cli.app import app

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_version_and_doctor():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and "1.0.1" in r.stdout
    assert "Taher Amine ELHOUARI" in r.stdout
    assert "https://www.taheramine.org" in r.stdout
    r = runner.invoke(app, ["doctor", "--json"])
    assert r.exit_code == 0 and '"network_required": false' in r.stdout
    assert '"author": "Taher Amine ELHOUARI"' in r.stdout
    assert '"website": "https://www.taheramine.org"' in r.stdout


def test_policies_list_validate():
    r = runner.invoke(app, ["policies", "list"])
    assert r.exit_code == 0 and "vendor-support" in r.stdout
    r = runner.invoke(app, ["policies", "validate", str(ROOT / "policies")])
    assert r.exit_code == 0


def test_discover_json():
    r = runner.invoke(app, ["discover", str(ROOT / "samples/enterprise-incident"), "--json"])
    assert r.exit_code == 0
    assert "semantic_counts" in r.stdout


def test_plan():
    r = runner.invoke(
        app,
        ["plan", str(ROOT / "samples/enterprise-incident"), "--policy", "vendor-support", "--json"],
    )
    assert r.exit_code == 0 and "remove-secrets" in r.stdout


def test_about_and_help_include_attribution():
    r = runner.invoke(app, ["about", "--json"])
    assert r.exit_code == 0
    assert '"creator": "Taher Amine ELHOUARI"' in r.stdout
    assert '"github": "MrTaherAmine"' in r.stdout
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    assert "Taher Amine ELHOUARI" in r.stdout
