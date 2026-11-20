"""Exercise real files and Git indexes; no credential values in reports."""

import json
import subprocess

from scitex_security.credentials import audit_credentials


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=True
    )


def test_tracked_plaintext_is_redacted_and_read_only(tmp_path):
    # Arrange
    git(tmp_path, "init", "-q")
    private = tmp_path / ".env"
    private.write_text('export SERVICE_PASSWORD="fixture-sensitive-value"\n')
    private.chmod(0o644)
    git(tmp_path, "add", ".env")
    before = private.read_bytes()
    # Act
    result = audit_credentials(str(tmp_path))
    # Assert
    assert {"CRED_PERMISSIONS", "CRED_PLAINTEXT_STORAGE", "CRED_TRACKED_PLAINTEXT"} <= {
        f["code"] for f in result["findings"]
    }
    assert "fixture-sensitive-value" not in json.dumps(result)
    assert private.read_bytes() == before
    assert private.stat().st_mode & 0o777 == 0o644


def test_environment_reference_is_not_literal(tmp_path):
    # Arrange
    git(tmp_path, "init", "-q")
    path = tmp_path / ".env"
    path.write_text('export SERVICE_PASSWORD="${PRIVATE_PASSWORD}"\n')
    path.chmod(0o600)
    git(tmp_path, "add", ".env")
    # Act
    result = audit_credentials(str(tmp_path))
    # Assert
    assert result["status"] == "ok"
    assert result["coverage"]["git_blobs"] == 1


def test_index_checked_even_when_working_copy_is_cleaned(tmp_path):
    # Arrange
    git(tmp_path, "init", "-q")
    path = tmp_path / ".env"
    path.write_text("API_TOKEN=fixture-original-sensitive-value\n")
    git(tmp_path, "add", ".env")
    path.write_text("API_TOKEN=${TOKEN_FROM_STORE}\n")
    path.chmod(0o600)
    # Act
    result = audit_credentials(str(tmp_path))
    # Assert
    assert any(f["code"] == "CRED_TRACKED_PLAINTEXT" for f in result["findings"])
    assert "fixture-original-sensitive-value" not in json.dumps(result)


def test_discovered_directory_symlinks_are_not_traversed(tmp_path):
    # Arrange
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "key").write_text("PASSWORD=fixture-value\n")
    (private / "link").symlink_to(outside, target_is_directory=True)
    # Act
    result = audit_credentials(str(tmp_path), secret_paths=["private"])
    # Assert
    assert result["findings"] == []
    assert result["coverage"]["git"] == "skipped_not_repository"


def test_large_blob_reports_incomplete_coverage(tmp_path):
    # Arrange
    git(tmp_path, "init", "-q")
    path = tmp_path / ".env"
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    path.chmod(0o600)
    git(tmp_path, "add", ".env")
    # Act
    result = audit_credentials(str(tmp_path))
    # Assert
    assert result["status"] == "error"
    assert result["coverage"]["truncated"]


def test_private_key_detection_omits_key_material(tmp_path):
    # Arrange
    ssh = tmp_path / ".ssh"
    ssh.mkdir(mode=0o700)
    path = ssh / "id_ed25519"
    path.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-key-material\n")
    path.chmod(0o600)
    # Act
    result = audit_credentials(str(tmp_path))
    # Assert
    assert any(f["code"] == "CRED_PRIVATE_KEY_STORAGE" for f in result["findings"])
    assert "fixture-key-material" not in json.dumps(result)


def test_configured_encryption_filter_is_not_proof_of_encrypted_index(tmp_path):
    # Arrange
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'config', 'filter.fake.clean', 'cat')
    (tmp_path / '.gitattributes').write_text('.env filter=fake\n')
    path = tmp_path / '.env'
    path.write_text('SERVICE_PASSWORD=fixture-unprotected-index\n')
    path.chmod(0o600)
    git(tmp_path, 'add', '.gitattributes', '.env')
    # Act
    result = audit_credentials(str(tmp_path))
    # Assert
    assert any(f['code'] == 'CRED_TRACKED_PLAINTEXT' for f in result['findings'])
    assert 'fixture-unprotected-index' not in json.dumps(result)


def test_cli_returns_findings_without_exposing_values(tmp_path):
    # Arrange
    from click.testing import CliRunner

    from scitex_security.cli import main
    path = tmp_path / '.env'
    path.write_text('PASSWORD=fixture-cli-sensitive-value\n')
    path.chmod(0o600)
    # Act
    result = CliRunner().invoke(main, ['check-credentials', str(tmp_path), '--json'])
    # Assert
    assert result.exit_code == 1
    assert json.loads(result.output)['results']['credentials']['status'] == 'findings'
    assert 'fixture-cli-sensitive-value' not in result.output


def test_openpgp_private_export_is_not_confused_with_public_ciphertext(tmp_path):
    # Arrange
    git(tmp_path, 'init', '-q')
    private = tmp_path / 'export.key'
    private.write_text('-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture-openpgp-private-data\n')
    private.chmod(0o600)
    git(tmp_path, 'add', 'export.key')
    # Act
    result = audit_credentials(str(tmp_path))
    # Assert
    assert any(f['code'] == 'CRED_TRACKED_PRIVATE_KEY' for f in result['findings'])
    assert 'fixture-openpgp-private-data' not in json.dumps(result)
